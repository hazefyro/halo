# Test Checklist

## Root package: `goauth`

- [x] `TestNewRequiresStateStore` verifies `New` returns an error when no `StateStore` is provided.
- [x] `TestNewWithStateStore` verifies `New` accepts `WithStateStore` and returns a usable `Registry`.
- [x] `TestRegisterAcceptsValidProviderNames` verifies `Register` accepts letters, numbers, `_`, and `-`.
- [x] `TestRegisterRejectsInvalidProviderNames` verifies `Register` rejects invalid provider name characters.
- [x] `TestRegisterRejectsDuplicateProviders` verifies `Register` rejects duplicate provider names.
- [x] `TestGetReturnsRegisteredProvider` verifies `Get` returns a known provider.
- [x] `TestGetReturnsErrProviderNotFound` verifies `Get` returns `ErrProviderNotFound` for an unknown provider.
- [x] `TestBeginAuthReturnsErrProviderNotFound` verifies `BeginAuth` fails for an unknown provider.
- [x] `TestBeginAuthCallsProviderWithGeneratedState` verifies `BeginAuth` passes a generated state to the provider.
- [x] `TestBeginAuthStoresGeneratedState` verifies `BeginAuth` stores state with the provider name.
- [x] `TestBeginAuthRedirectsToProviderURL` verifies `BeginAuth` writes `307 Temporary Redirect`.
- [x] `TestBeginAuthReturnsProviderError` verifies provider `BeginAuth` errors are returned without storing state.
- [x] `TestBeginAuthReturnsStateStoreError` verifies state store `Store` errors are returned without redirecting.
- [x] `TestCallbackRequiresNextHandler` verifies `Callback` returns an error when `next` is nil.
- [x] `TestCallbackReturnsErrProviderNotFound` verifies `Callback` fails for an unknown provider.
- [x] `TestCallbackReturnsCallbackErrorFromQuery` verifies `?error=` and `?error_description=` become `CallbackError`.
- [x] `TestCallbackVerifiesStateBeforeCompleteAuth` verifies callback state is checked before auth completion.
- [x] `TestCallbackReturnsErrStateMismatch` verifies failed state verification returns `ErrStateMismatch`.
- [x] `TestCallbackClearsStateAfterVerification` verifies stored state is cleared after successful verification.
- [x] `TestCallbackCallsCompleteAuth` verifies provider `CompleteAuth` is called after state verification.
- [x] `TestCallbackReturnsCompleteAuthError` verifies provider errors are returned and `next` is not called.
- [x] `TestCallbackStoresAuthResultInContext` verifies `AuthResult` is added to request context before `next`.
- [x] `TestIdentityFromContextMissing` verifies `IdentityFromContext` errors when no identity is present.
- [x] `TestIdentityFromContextReturnsIdentity` verifies `IdentityFromContext` returns callback identity.
- [x] `TestStoreIdentityInContext` verifies `StoreIdentityInContext` stores identity-only auth data.
- [x] `TestCredentialsFromContextMissing` verifies `CredentialsFromContext` errors when credentials are absent.
- [x] `TestCredentialsFromContextEmptyAccessToken` verifies empty access token credentials are rejected.
- [x] `TestCredentialsFromContextReturnsCredentials` verifies credentials are returned from callback context.
- [x] `TestProviderFromContextReturnsProvider` verifies provider name is read from context identity.
- [x] `TestProviderFromContextMissing` verifies missing auth result returns an empty provider string.
- [x] `TestRawDataFromContextMissing` verifies `RawDataFromContext` errors when raw data is absent.
- [x] `TestRawDataFromContextReturnsRawData` verifies raw provider data is returned from callback context.
- [x] `TestAuthRequiredUnauthorized` verifies `AuthRequired` writes `401 Unauthorized` without identity.
- [x] `TestAuthRequiredAllowsAuthenticatedRequest` verifies `AuthRequired` calls `next` when identity exists.
- [x] `TestCallbackErrorErrorWithDescription` verifies `CallbackError.Error` includes code and description.
- [x] `TestCallbackErrorErrorWithoutDescription` verifies `CallbackError.Error` includes only the code.

## Cookie state store

- [x] `TestNewCookieStateStoreRejectsShortSecret` verifies secure stores require at least 32 bytes.
- [x] `TestNewCookieStateStoreCreatesSecureStore` verifies secure stores set secure cookies.
- [x] `TestNewInsecureCookieStateStoreRejectsShortSecret` verifies insecure stores require at least 32 bytes.
- [x] `TestNewInsecureCookieStateStoreCreatesInsecureStore` verifies insecure stores do not set secure cookies.
- [x] `TestCookieStateStoreStoreUsesProviderCookieName` verifies state cookies are provider-specific.
- [x] `TestCookieStateStoreStoreSignsState` verifies raw state is not stored in the cookie value.
- [x] `TestCookieStateStoreStoreSetsCookieAttributes` verifies `Path=/`, `HttpOnly`, `SameSite=Lax`, and `MaxAge=300`.
- [x] `TestCookieStateStoreStoreSetsSecureFlag` verifies secure stores write `Secure=true`.
- [x] `TestCookieStateStoreStoreClearsSecureFlagForInsecureStore` verifies insecure stores write `Secure=false`.
- [x] `TestCookieStateStoreVerifyAcceptsMatchingState` verifies matching state, provider, and signature pass.
- [x] `TestCookieStateStoreVerifyRejectsMissingCookie` verifies missing cookies return `ErrStateMismatch`.
- [x] `TestCookieStateStoreVerifyRejectsWrongProvider` verifies provider name mismatches return `ErrStateMismatch`.
- [x] `TestCookieStateStoreVerifyRejectsWrongState` verifies state mismatches return `ErrStateMismatch`.
- [x] `TestCookieStateStoreVerifyRejectsTamperedSignature` verifies tampered signatures return `ErrStateMismatch`.
- [x] `TestCookieStateStoreClearExpiresCookie` verifies `Clear` writes an expired provider-specific cookie.
- [x] `TestCookieStateStoreClearPreservesCookieAttributes` verifies `Clear` preserves path, HTTP-only, SameSite, and secure settings.

## Internal utilities

- [x] `TestSignReturnsDeterministicHMAC` verifies `hmacutil.Sign` returns deterministic SHA-256 HMAC hex.
- [x] `TestVerifyAcceptsMatchingSignature` verifies `hmacutil.Verify` accepts matching value and signature.
- [x] `TestVerifyRejectsMismatchedValue` verifies `hmacutil.Verify` rejects mismatched values.
- [x] `TestVerifyRejectsMismatchedSignature` verifies `hmacutil.Verify` rejects mismatched signatures.
- [x] `TestRandomStateFormat` verifies `randstate.RandomState` returns a 32-character hex string.
- [x] `TestRandomStateUniqueness` verifies repeated `randstate.RandomState` calls return different values.
- [x] `TestGetStringReturnsStringValue` verifies `maputil.GetString` returns string values.
- [x] `TestGetStringReturnsEmptyForMissingOrNonString` verifies missing and non-string values return empty string.
- [x] `TestGetIDReturnsStringID` verifies `maputil.GetID` returns string IDs unchanged.
- [x] `TestGetIDConvertsFloat64ID` verifies `float64` IDs are converted without decimals.
- [x] `TestGetIDConvertsJSONNumberID` verifies `json.Number` IDs are converted without precision loss.
- [x] `TestGetIDReturnsEmptyForUnsupportedValues` verifies unsupported ID values return empty string.
- [x] `TestApplyAppliesOptionsInOrder` verifies `provideropts.Apply` applies all options in order.
- [x] `TestWithScopesStoresScopes` verifies `WithScopes` stores replacement scopes.
- [x] `TestWithAdditionalScopesStoresAdditionalScopes` verifies `WithAdditionalScopes` stores appended scopes.
- [x] `TestWithAuthCodeOptionsStoresOptions` verifies `WithAuthCodeOptions` preserves custom auth code options.
- [x] `TestWithHTTPClientStoresClient` verifies `WithHTTPClient` stores the supplied HTTP client.
- [x] `TestWithUserInfoURLStoresURL` verifies `WithUserInfoURL` stores the supplied user info URL.
- [x] `TestWithEndpointStoresEndpoint` verifies `WithEndpoint` stores the supplied OAuth endpoint.

## Internal OAuth helper

- [x] `TestFetchUserInfoExchangesCode` verifies `oauthutil.FetchUserInfo` exchanges callback code for a token.
- [x] `TestFetchUserInfoFetchesUserInfoWithTokenClient` verifies user info is fetched with the token-backed client.
- [x] `TestFetchUserInfoReturnsExchangeError` verifies token exchange failures are returned.
- [x] `TestFetchUserInfoReturnsHTTPError` verifies user info HTTP failures are returned.
- [x] `TestFetchUserInfoReturnsNon2xxError` verifies non-2xx user info responses are returned as errors.
- [x] `TestFetchUserInfoUsesJSONNumber` verifies decoded user info preserves numbers as `json.Number`.
- [x] `TestFetchUserInfoReturnsInvalidJSONError` verifies invalid JSON is returned as an error.
- [x] `TestFetchUserInfoLimitsResponseBody` verifies responses over 1 MB are rejected or fail decoding.
- [x] `TestRefreshTokenReturnsCredentials` verifies refreshed OAuth tokens become `Credentials`.
- [x] `TestRefreshTokenKeepsOldRefreshToken` verifies the old refresh token is kept when no new one is returned.
- [x] `TestRefreshTokenReturnsTokenSourceError` verifies token source errors are returned.

## Google provider

- [x] `TestGoogleNewDefaultScopes` verifies default scopes are `openid`, `email`, and `profile`.
- [x] `TestGoogleNewWithScopes` verifies `WithScopes` replaces default scopes.
- [x] `TestGoogleNewWithAdditionalScopes` verifies `WithAdditionalScopes` appends to defaults.
- [x] `TestGoogleNewWithEndpoint` verifies `WithEndpoint` overrides the OAuth endpoint.
- [x] `TestGoogleNewWithUserInfoURL` verifies `WithUserInfoURL` overrides the user info URL.
- [x] `TestGoogleNewWithHTTPClient` verifies `WithHTTPClient` is used for provider requests.
- [x] `TestGoogleNewWithAuthCodeOptions` verifies custom auth code options are preserved.
- [x] `TestGoogleName` verifies `Name` returns `google`.
- [x] `TestGoogleBeginAuthIncludesState` verifies auth URLs include the supplied state.
- [x] `TestGoogleBeginAuthRequestsOfflineAccess` verifies auth URLs include `access_type=offline`.
- [x] `TestGoogleBeginAuthIncludesCustomOptions` verifies custom auth code options are included.
- [x] `TestGoogleCompleteAuthRequiresCode` verifies missing `code` returns `ErrMissingCode`.
- [x] `TestGoogleCompleteAuthFetchesUserInfo` verifies code exchange and configured user info fetch happen.
- [x] `TestGoogleCompleteAuthMapsIdentity` verifies `sub`, `email`, `name`, and `picture` map into `Identity`.
- [x] `TestGoogleCompleteAuthSetsProvider` verifies `Identity.Provider` is `google`.
- [x] `TestGoogleCompleteAuthReturnsCredentials` verifies OAuth token fields map into credentials.
- [x] `TestGoogleCompleteAuthPreservesRawData` verifies raw user info data is preserved.
- [x] `TestGoogleCompleteAuthRequiresUserID` verifies missing `sub` returns `ErrMissingUserID`.
- [x] `TestGoogleCompleteAuthReturnsOAuthErrors` verifies token exchange and user info errors are returned.
- [x] `TestGoogleRefreshToken` verifies refresh tokens are exchanged through the configured endpoint.
- [x] `TestGoogleRefreshTokenUsesCustomHTTPClient` verifies refresh requests use the custom HTTP client.

## Discord provider

- [x] `TestDiscordNewDefaultScopes` verifies default scopes are `identify` and `email`.
- [x] `TestDiscordNewWithScopes` verifies `WithScopes` replaces default scopes.
- [x] `TestDiscordNewWithAdditionalScopes` verifies `WithAdditionalScopes` appends to defaults.
- [x] `TestDiscordNewWithEndpoint` verifies `WithEndpoint` overrides the OAuth endpoint.
- [x] `TestDiscordNewWithUserInfoURL` verifies `WithUserInfoURL` overrides the user info URL.
- [x] `TestDiscordNewWithHTTPClient` verifies `WithHTTPClient` is used for provider requests.
- [x] `TestDiscordNewWithAuthCodeOptions` verifies custom auth code options are preserved.
- [x] `TestDiscordName` verifies `Name` returns `discord`.
- [x] `TestDiscordBeginAuthIncludesState` verifies auth URLs include the supplied state.
- [x] `TestDiscordBeginAuthIncludesCustomOptions` verifies custom auth code options are included.
- [x] `TestDiscordCompleteAuthRequiresCode` verifies missing `code` returns `ErrMissingCode`.
- [x] `TestDiscordCompleteAuthFetchesUserInfo` verifies code exchange and configured user info fetch happen.
- [x] `TestDiscordCompleteAuthMapsIdentity` verifies `id`, `email`, `username`, and `global_name` map into `Identity`.
- [x] `TestDiscordCompleteAuthBuildsAvatarURL` verifies avatar hashes become Discord CDN URLs.
- [x] `TestDiscordCompleteAuthAllowsMissingAvatar` verifies missing avatar leaves `AvatarURL` empty.
- [x] `TestDiscordCompleteAuthSetsProvider` verifies `Identity.Provider` is `discord`.
- [x] `TestDiscordCompleteAuthReturnsCredentials` verifies OAuth token fields map into credentials.
- [x] `TestDiscordCompleteAuthPreservesRawData` verifies raw user info data is preserved.
- [x] `TestDiscordCompleteAuthRequiresUserID` verifies missing `id` returns `ErrMissingUserID`.
- [x] `TestDiscordCompleteAuthReturnsOAuthErrors` verifies token exchange and user info errors are returned.
- [x] `TestDiscordRefreshToken` verifies refresh tokens are exchanged through the configured endpoint.
- [x] `TestDiscordRefreshTokenUsesCustomHTTPClient` verifies refresh requests use the custom HTTP client.

## GitHub provider

- [x] `TestGitHubNewDefaultScopes` verifies default scopes are `read:user` and `user:email`.
- [x] `TestGitHubNewWithScopes` verifies `WithScopes` replaces default scopes.
- [x] `TestGitHubNewWithAdditionalScopes` verifies `WithAdditionalScopes` appends to defaults.
- [x] `TestGitHubNewWithEndpoint` verifies `WithEndpoint` overrides the OAuth endpoint.
- [x] `TestGitHubNewWithUserInfoURL` verifies `WithUserInfoURL` overrides the user info URL.
- [x] `TestGitHubNewWithHTTPClient` verifies `WithHTTPClient` is used for provider requests.
- [x] `TestGitHubNewWithAuthCodeOptions` verifies custom auth code options are preserved.
- [x] `TestGitHubName` verifies `Name` returns `github`.
- [x] `TestGitHubBeginAuthIncludesState` verifies auth URLs include the supplied state.
- [x] `TestGitHubBeginAuthIncludesCustomOptions` verifies custom auth code options are included.
- [x] `TestGitHubCompleteAuthRequiresCode` verifies missing `code` returns `ErrMissingCode`.
- [x] `TestGitHubCompleteAuthFetchesUserInfo` verifies code exchange and configured user info fetch happen.
- [x] `TestGitHubCompleteAuthMapsIdentity` verifies `id`, `email`, `login`, `name`, and `avatar_url` map into `Identity`.
- [x] `TestGitHubCompleteAuthSetsProvider` verifies `Identity.Provider` is `github`.
- [x] `TestGitHubCompleteAuthReturnsCredentials` verifies OAuth token fields map into credentials.
- [x] `TestGitHubCompleteAuthPreservesRawData` verifies raw user info data is preserved.
- [x] `TestGitHubCompleteAuthRequiresUserID` verifies missing `id` returns `ErrMissingUserID`.
- [x] `TestGitHubCompleteAuthReturnsOAuthErrors` verifies token exchange and user info errors are returned.
- [x] `TestGitHubCompleteAuthSkipsEmailEndpointWhenEmailPresent` verifies `/user/emails` is not called when email exists.
- [x] `TestGitHubCompleteAuthFetchesPrimaryEmail` verifies `/user/emails` is fetched when user info email is empty.
- [x] `TestGitHubCompleteAuthUsesPrimaryVerifiedEmail` verifies primary verified email is selected.
- [x] `TestGitHubCompleteAuthAllowsNoPrimaryVerifiedEmail` verifies email stays empty without a primary verified email.
- [x] `TestGitHubCompleteAuthReturnsEmailEndpointStatusError` verifies non-2xx email responses return errors.
- [x] `TestGitHubCompleteAuthReturnsEmailEndpointJSONError` verifies invalid email JSON returns errors.

## Integration and CI

- [x] `TestRegistryOAuthFlow` verifies an end-to-end registry flow using fake provider and fake state store.
- [x] `TestProvidersUseLocalOAuthServers` verifies provider tests use local `httptest.Server` OAuth endpoints.
- [x] `TestProvidersDoNotUseLiveNetwork` verifies tests avoid live Google, Discord, and GitHub calls.
- [x] `TestGoTestAllPackagesPasses` verifies `go test ./...` passes locally.
- [x] `TestGoVetAllPackagesPasses` verifies `go vet ./...` passes locally.
- [x] `TestCIRunsVetAndTests` verifies CI runs `go vet ./...` and `go test ./...` on pull requests.
