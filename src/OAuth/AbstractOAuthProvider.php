<?php

declare(strict_types=1);

namespace MonkeysLegion\Auth\OAuth;

use MonkeysLegion\Auth\Contract\OAuthProviderInterface;
use RuntimeException;

/**
 * Base class for OAuth providers.
 */
abstract class AbstractOAuthProvider implements OAuthProviderInterface
{
    public function __construct(
        protected readonly string $clientId,
        protected readonly string $clientSecret,
        protected readonly string $redirectUri
    ) {}

    abstract public function getName(): string;
    abstract protected function getAuthorizationEndpoint(): string;
    abstract protected function getTokenEndpoint(): string;
    abstract protected function getUserInfoEndpoint(): string;
    abstract protected function getDefaultScopes(): array;
    abstract protected function parseUserInfo(array $data): array;

    public function getAuthorizationUrl(string $state, array $scopes = []): string
    {
        $scopes = array_merge($this->getDefaultScopes(), $scopes);

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'state' => $state,
        ];

        return $this->getAuthorizationEndpoint() . '?' . http_build_query($params);
    }

    public function getAccessToken(string $code): array
    {
        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->redirectUri,
        ];

        $response = $this->httpPost($this->getTokenEndpoint(), $params);

        if (!isset($response['access_token'])) {
            throw new RuntimeException(
                $response['error_description'] ?? $response['error'] ?? 'Failed to get access token'
            );
        }

        return [
            'access_token' => $response['access_token'],
            'refresh_token' => $response['refresh_token'] ?? null,
            'expires_in' => $response['expires_in'] ?? 3600,
        ];
    }

    public function getUserInfo(string $accessToken): array
    {
        $response = $this->httpGet(
            $this->getUserInfoEndpoint(),
            ['Authorization' => 'Bearer ' . $accessToken]
        );

        return $this->parseUserInfo($response);
    }

    public function getUser(string $accessToken): \MonkeysLegion\Auth\DTO\OAuthUser
    {
        $userInfo = $this->getUserInfo($accessToken);

        return new \MonkeysLegion\Auth\DTO\OAuthUser(
            providerId: $userInfo['id'],
            provider: $this->getName(),
            email: $userInfo['email'] ?? null,
            name: $userInfo['name'] ?? null,
            avatar: $userInfo['avatar'] ?? null,
            nickname: $userInfo['nickname'] ?? null,
            raw: $userInfo,
        );
    }

    public function refreshToken(string $refreshToken): array
    {
        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $refreshToken,
            'grant_type' => 'refresh_token',
        ];

        $response = $this->httpPost($this->getTokenEndpoint(), $params);

        if (!isset($response['access_token'])) {
            throw new RuntimeException(
                $response['error_description'] ?? $response['error'] ?? 'Failed to refresh token'
            );
        }

        return [
            'access_token' => $response['access_token'],
            'refresh_token' => $response['refresh_token'] ?? $refreshToken,
            'expires_in' => $response['expires_in'] ?? 3600,
        ];
    }

    protected function httpPost(string $url, array $data): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_TIMEOUT => 30,
        ]);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        if ($response === false) {
            throw new RuntimeException('HTTP request failed: ' . $error);
        }
        return json_decode($response, true, 512, JSON_THROW_ON_ERROR);
    }

    protected function httpGet(string $url, array $headers = []): array
    {
        $ch = curl_init($url);
        $headerLines = ['Accept: application/json'];
        foreach ($headers as $name => $value) {
            $headerLines[] = "{$name}: {$value}";
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_TIMEOUT => 30,
        ]);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        if ($response === false) {
            throw new RuntimeException('HTTP request failed: ' . $error);
        }
        return json_decode($response, true, 512, JSON_THROW_ON_ERROR);
    }
}
