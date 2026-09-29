<?php
declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\Contract\OAuthProviderInterface;
use MonkeysLegion\Auth\DTO\OAuthUser;

/**
 * MonKeysLegion Framework — Auth Package
 *
 * Base class for OAuth 2.0 providers.
 *
 * Implements the common OAuth 2.0 Authorization Code flow:
 *   1. Build authorization URL with state + PKCE
 *   2. Exchange authorization code for access token
 *   3. Fetch user info from provider's API
 *   4. Map to normalized OAuthUser DTO
 *
 * @copyright 2026 MonKeysCloud Team
 * @license   MIT
 */
abstract class AbstractOAuthProvider implements OAuthProviderInterface
{
    protected string $codeVerifier = '';
    protected string $codeChallenge = '';

    public function __construct(
        protected readonly string $clientId,
        protected readonly string $clientSecret,
        protected readonly string $redirectUri,
        protected readonly array $scopes = [],
    ) {}

    /**
     * Get the authorization endpoint URL.
     */
    abstract protected function getAuthUrl(): string;

    /**
     * Get the token exchange endpoint URL.
     */
    abstract protected function getTokenUrl(): string;

    /**
     * Get the user info endpoint URL.
     */
    abstract protected function getUserUrl(): string;

    /**
     * Map the raw user info response to an OAuthUser DTO.
     *
     * @param array<string, mixed> $userInfo
     */
    abstract protected function mapToUser(array $userInfo): OAuthUser;

    public function getAuthorizationUrl(string $state, array $scopes = []): string
    {
        $this->generatePkce();

        $params = [
            'client_id'             => $this->clientId,
            'redirect_uri'          => $this->redirectUri,
            'response_type'         => 'code',
            'scope'                 => implode(' ', array_merge($this->scopes, $scopes)),
            'state'                 => $state,
            'code_challenge'        => $this->codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        return $this->getAuthUrl() . '?' . http_build_query($params);
    }

    public function getAccessToken(string $code): array
    {
        $params = [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'code'          => $code,
            'code_verifier' => $this->codeVerifier,
        ];

        $response = $this->httpPost($this->getTokenUrl(), $params);
        $data = json_decode($response, true);

        if (!is_array($data) || !isset($data['access_token'])) {
            throw new \RuntimeException('Failed to get access token: ' . $response);
        }

        return [
            'access_token'  => $data['access_token'],
            'refresh_token' => $data['refresh_token'] ?? null,
            'expires_in'    => $data['expires_in'] ?? 3600,
        ];
    }

    public function getUserInfo(string $accessToken): array
    {
        $response = $this->httpGet($this->getUserUrl(), [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/json',
        ]);

        $data = json_decode($response, true);
        return is_array($data) ? $data : [];
    }

    public function getUser(string $accessToken): OAuthUser
    {
        $userInfo = $this->getUserInfo($accessToken);
        return $this->mapToUser($userInfo);
    }

    public function refreshToken(string $refreshToken): array
    {
        $params = [
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $refreshToken,
        ];

        $response = $this->httpPost($this->getTokenUrl(), $params);
        $data = json_decode($response, true);

        if (!is_array($data) || !isset($data['access_token'])) {
            throw new \RuntimeException('Failed to refresh token: ' . $response);
        }

        return [
            'access_token'  => $data['access_token'],
            'refresh_token' => $data['refresh_token'] ?? $refreshToken,
            'expires_in'    => $data['expires_in'] ?? 3600,
        ];
    }

    /**
     * Generate a random state parameter for CSRF protection.
     */
    public static function generateState(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Generate PKCE code verifier and challenge.
     */
    protected function generatePkce(): void
    {
        $this->codeVerifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $this->codeVerifier, true)), '+/', '-_'), '=');
    }

    /**
     * HTTP GET request with cURL.
     *
     * @param list<string> $headers
     */
    protected function httpGet(string $url, array $headers = []): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new \RuntimeException('HTTP GET failed: ' . $error);
        }

        return (string) $response;
    }

    /**
     * HTTP POST request with cURL (form-encoded body).
     *
     * @param array<string, string> $params
     */
    protected function httpPost(string $url, array $params): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($params),
            CURLOPT_HTTPHEADER     => ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new \RuntimeException('HTTP POST failed: ' . $error);
        }

        return (string) $response;
    }
}
