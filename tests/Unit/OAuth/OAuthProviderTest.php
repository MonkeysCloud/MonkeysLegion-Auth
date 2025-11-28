<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\Tests\Unit\OAuth;

use MonkeysLegion\Auth\OAuth\GoogleProvider;
use MonkeysLegion\Auth\OAuth\GitHubProvider;
use MonkeysLegion\Auth\Tests\TestCase;

class OAuthProviderTest extends TestCase
{
    public function testGoogleProviderName(): void
    {
        $provider = new GoogleProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $this->assertEquals('google', $provider->getName());
    }

    public function testGoogleAuthorizationUrl(): void
    {
        $provider = new GoogleProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $url = $provider->getAuthorizationUrl('state-token');

        $this->assertStringContainsString('accounts.google.com', $url);
        $this->assertStringContainsString('client_id=test-client-id', $url);
        $this->assertStringContainsString('redirect_uri=', $url);
        $this->assertStringContainsString('state=state-token', $url);
        $this->assertStringContainsString('response_type=code', $url);
        $this->assertStringContainsString('scope=', $url);
    }

    public function testGoogleAuthorizationUrlWithScopes(): void
    {
        $provider = new GoogleProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $url = $provider->getAuthorizationUrl('state-token', ['calendar.readonly']);

        $this->assertStringContainsString('calendar.readonly', urldecode($url));
    }

    public function testGitHubProviderName(): void
    {
        $provider = new GitHubProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $this->assertEquals('github', $provider->getName());
    }

    public function testGitHubAuthorizationUrl(): void
    {
        $provider = new GitHubProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $url = $provider->getAuthorizationUrl('state-token');

        $this->assertStringContainsString('github.com/login/oauth/authorize', $url);
        $this->assertStringContainsString('client_id=test-client-id', $url);
        $this->assertStringContainsString('state=state-token', $url);
    }

    public function testGitHubDefaultScopes(): void
    {
        $provider = new GitHubProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $url = $provider->getAuthorizationUrl('state-token');

        $this->assertStringContainsString('user%3Aemail', $url);
    }

    public function testGitHubWithAdditionalScopes(): void
    {
        $provider = new GitHubProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $url = $provider->getAuthorizationUrl('state-token', ['repo', 'gist']);

        $decodedUrl = urldecode($url);
        $this->assertStringContainsString('repo', $decodedUrl);
        $this->assertStringContainsString('gist', $decodedUrl);
    }

    public function testStateParameterIsIncluded(): void
    {
        $provider = new GoogleProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: 'https://example.com/callback',
        );

        $state = bin2hex(random_bytes(16));
        $url = $provider->getAuthorizationUrl($state);

        $this->assertStringContainsString("state={$state}", $url);
    }

    public function testRedirectUriIsEncoded(): void
    {
        $redirectUri = 'https://example.com/auth/callback?source=google';
        
        $provider = new GoogleProvider(
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            redirectUri: $redirectUri,
        );

        $url = $provider->getAuthorizationUrl('state');

        $this->assertStringContainsString(urlencode($redirectUri), $url);
    }
}
