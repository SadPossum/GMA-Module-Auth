namespace Gma.Modules.Auth.Application.Handlers;

using Gma.Framework.Cqrs;
using Gma.Framework.Results;
using Gma.Framework.Runtime.Identity;
using Gma.Framework.Runtime.Time;
using Gma.Modules.Auth.Application.Commands;
using Gma.Modules.Auth.Application.ExternalAuthentication;
using Gma.Modules.Auth.Application.Ports;
using Gma.Modules.Auth.Contracts;
using Gma.Modules.Auth.Domain.Aggregates;
using Gma.Modules.Auth.Domain.Entities;
using Gma.Modules.Auth.Domain.Enums;
using Gma.Modules.Auth.Domain.Errors;
using Gma.Modules.Auth.Domain.Repositories;
using Gma.Modules.Auth.Domain.Services;
using Gma.Modules.Auth.Domain.ValueObjects;
using Microsoft.Extensions.Options;
using Gma.Modules.Auth.Application.Security;

internal sealed class ExchangeExternalAuthenticationCommandHandler(
    IExternalAuthenticationExchangeStore exchangeStore,
    IMemberRepository memberRepository,
    ITokenService tokenService,
    IRefreshTokenHashingService tokenHashingService,
    IOptions<AuthApplicationOptions> options,
    IAuthScopeContext scopeContext,
    ISystemClock clock,
    IIdGenerator idGenerator)
    : AuthCommandHandlerBase(tokenService, tokenHashingService, clock, idGenerator),
        ICommandHandler<ExchangeExternalAuthenticationCommand, ExternalAuthenticationResponse>
{
    public async Task<Result<ExternalAuthenticationResponse>> HandleAsync(
        ExchangeExternalAuthenticationCommand command,
        CancellationToken cancellationToken)
    {
        ExternalAuthenticationExchange? exchange = await this.ConsumeExchangeAsync(command.Code, cancellationToken)
            .ConfigureAwait(false);
        if (exchange is null || !string.Equals(exchange.ScopeId, scopeContext.ScopeId, StringComparison.Ordinal))
        {
            return Result.Failure<ExternalAuthenticationResponse>(AuthApplicationErrors.ExternalExchangeInvalid);
        }

        return exchange.Intent switch
        {
            ExternalAuthenticationIntent.SignIn => await this.SignInAsync(exchange, command, cancellationToken).ConfigureAwait(false),
            ExternalAuthenticationIntent.Link => await this.LinkAsync(exchange, command, cancellationToken).ConfigureAwait(false),
            _ => Result.Failure<ExternalAuthenticationResponse>(AuthApplicationErrors.ExternalExchangeInvalid),
        };
    }

    private async Task<ExternalAuthenticationExchange?> ConsumeExchangeAsync(
        string code,
        CancellationToken cancellationToken)
    {
        foreach (string candidateHash in this.TokenHashingService.GetCandidateHashes(code.Trim()))
        {
            ExternalAuthenticationExchange? exchange = await exchangeStore
                .ConsumeAsync(candidateHash, this.Clock.UtcNow, cancellationToken)
                .ConfigureAwait(false);
            if (exchange is not null)
            {
                return exchange;
            }
        }

        return null;
    }

    private async Task<Result<ExternalAuthenticationResponse>> SignInAsync(
        ExternalAuthenticationExchange exchange,
        ExchangeExternalAuthenticationCommand command,
        CancellationToken cancellationToken)
    {
        Member? member = await memberRepository
            .GetByExternalIdentityAsync(exchange.Issuer, exchange.Subject, cancellationToken)
            .ConfigureAwait(false);

        if (member is null)
        {
            Result<Member> registration = await this.RegisterExternalMemberAsync(exchange, cancellationToken)
                .ConfigureAwait(false);
            if (registration.IsFailure)
            {
                return Result.Failure<ExternalAuthenticationResponse>(registration.Error);
            }

            member = registration.Value;
        }

        MemberExternalIdentity identity = member.ExternalIdentities.Single(item =>
            item.Matches(exchange.Issuer, exchange.Subject));
        Result authenticated = member.MarkExternalIdentityAuthenticated(identity.Id, this.Clock.UtcNow);
        if (authenticated.IsFailure)
        {
            return Result.Failure<ExternalAuthenticationResponse>(authenticated.Error);
        }

        var tokens = this.CreateTokens(
            member.Id,
            member.ScopeId,
            TimeSpan.FromDays(options.Value.RefreshTokenLifetimeDays));
        Result<MemberSession> session = member.StartSession(
            tokens.SessionId,
            tokens.RefreshTokenHash,
            tokens.ExpiresAtUtc,
            this.Clock.UtcNow,
            MemberAuthenticationMethods.External(exchange.ProviderCode));
        if (session.IsFailure)
        {
            return Result.Failure<ExternalAuthenticationResponse>(session.Error);
        }

        Result authenticatedEvent = member.RecordAuthentication(
            tokens.SessionId,
            this.IdGenerator.NewId(),
            this.Clock.UtcNow,
            AuthenticationClientContext.NormalizeIpAddress(command.IpAddress),
            AuthenticationClientContext.NormalizeUserAgent(command.UserAgent));
        if (authenticatedEvent.IsFailure)
        {
            return Result.Failure<ExternalAuthenticationResponse>(authenticatedEvent.Error);
        }

        return Result.Success(new ExternalAuthenticationResponse(
            ExternalAuthenticationStatus.Authenticated,
            exchange.ProviderCode,
            tokens.AccessToken,
            tokens.RefreshToken,
            identity.Id.Value));
    }

    private async Task<Result<Member>> RegisterExternalMemberAsync(
        ExternalAuthenticationExchange exchange,
        CancellationToken cancellationToken)
    {
        if (!options.Value.SelfRegistration.ExternalEnabled)
        {
            return Result.Failure<Member>(AuthApplicationErrors.SelfRegistrationDisabled);
        }

        if (!exchange.EmailVerified || string.IsNullOrWhiteSpace(exchange.Email))
        {
            return Result.Failure<Member>(AuthApplicationErrors.ExternalVerifiedEmailRequired);
        }

        if (await memberRepository.UsernameExistsAsync(exchange.Email, cancellationToken).ConfigureAwait(false))
        {
            return Result.Failure<Member>(AuthApplicationErrors.ExternalAccountLinkRequired);
        }

        Result<Member> memberResult = Member.CreateExternal(
            new MemberId(this.IdGenerator.NewId()),
            exchange.ScopeId,
            exchange.Email,
            new MemberUsernameId(this.IdGenerator.NewId()),
            new MemberExternalIdentityId(this.IdGenerator.NewId()),
            exchange.ProviderCode,
            exchange.Issuer,
            exchange.Subject,
            this.IdGenerator.NewId(),
            this.Clock.UtcNow);
        if (memberResult.IsFailure)
        {
            return memberResult;
        }

        await memberRepository.AddAsync(memberResult.Value, cancellationToken).ConfigureAwait(false);
        return memberResult;
    }

    private async Task<Result<ExternalAuthenticationResponse>> LinkAsync(
        ExternalAuthenticationExchange exchange,
        ExchangeExternalAuthenticationCommand command,
        CancellationToken cancellationToken)
    {
        if (exchange.TargetMemberId is null ||
            exchange.TargetSessionId is null ||
            command.CurrentMemberId != exchange.TargetMemberId ||
            command.CurrentSessionId != exchange.TargetSessionId)
        {
            return Result.Failure<ExternalAuthenticationResponse>(AuthApplicationErrors.ExternalLinkAuthorizationRequired);
        }

        MemberId memberId = new(exchange.TargetMemberId.Value);
        Member? member = await memberRepository.GetByIdAsync(memberId, cancellationToken).ConfigureAwait(false);
        if (member is null)
        {
            return Result.Failure<ExternalAuthenticationResponse>(AuthApplicationErrors.MemberNotFound);
        }

        MemberSessionId sessionId = new(exchange.TargetSessionId.Value);
        MemberSession? session = member.Sessions.FirstOrDefault(item => item.Id == sessionId && item.IsActive);
        DateTimeOffset freshnessCutoff = this.Clock.UtcNow.AddMinutes(-options.Value.ExternalLinkSessionFreshnessMinutes);
        if (session is null || session.LoginDateTimeUtc < freshnessCutoff)
        {
            return Result.Failure<ExternalAuthenticationResponse>(AuthApplicationErrors.FreshAuthenticationRequired);
        }

        Member? existingOwner = await memberRepository
            .GetByExternalIdentityAsync(exchange.Issuer, exchange.Subject, cancellationToken)
            .ConfigureAwait(false);
        if (existingOwner is not null)
        {
            MemberExternalIdentity existingIdentity = existingOwner.ExternalIdentities.Single(item =>
                item.Matches(exchange.Issuer, exchange.Subject));
            return existingOwner.Id == member.Id
                ? Result.Success(new ExternalAuthenticationResponse(
                    ExternalAuthenticationStatus.Linked,
                    exchange.ProviderCode,
                    ExternalIdentityId: existingIdentity.Id.Value))
                : Result.Failure<ExternalAuthenticationResponse>(AuthApplicationErrors.ExternalIdentityAlreadyLinked);
        }

        Result<MemberExternalIdentity> linked = member.LinkExternalIdentity(
            new MemberExternalIdentityId(this.IdGenerator.NewId()),
            exchange.ProviderCode,
            exchange.Issuer,
            exchange.Subject,
            this.Clock.UtcNow);
        if (linked.IsFailure)
        {
            return Result.Failure<ExternalAuthenticationResponse>(linked.Error);
        }

        Result changed = member.RecordAuthenticationMethodChanged(
            MemberAuthenticationMethods.External(linked.Value.ProviderCode),
            MemberAuthenticationMethodChange.Added,
            this.IdGenerator.NewId(),
            this.Clock.UtcNow);
        return changed.IsSuccess
            ? Result.Success(new ExternalAuthenticationResponse(
                ExternalAuthenticationStatus.Linked,
                exchange.ProviderCode,
                ExternalIdentityId: linked.Value.Id.Value))
            : Result.Failure<ExternalAuthenticationResponse>(changed.Error);
    }
}
