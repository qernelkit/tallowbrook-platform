<?php

declare(strict_types=1);

namespace App\Services\Auth;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

/**
 * Links that let a merchant share an unpublished product page with a colleague for an hour.
 */
final class PreviewLinkTokens
{
    private Configuration $config;

    public function __construct(string $previewSecret, private readonly int $ttlMinutes = 60)
    {
        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded($previewSecret),
        );
    }

    public function issue(string $productId, DateTimeImmutable $now): string
    {
        return $this->config->builder()
            ->permittedFor('catalog-preview')
            ->relatedTo($productId)
            ->issuedAt($now)
            ->expiresAt($now->modify(sprintf('+%d minutes', $this->ttlMinutes)))
            ->getToken($this->config->signer(), $this->config->signingKey())
            ->toString();
    }

    public function productId(string $token, DateTimeImmutable $now): ?string
    {
        $parsed = $this->config->parser()->parse($token);
        if (!$parsed instanceof Plain || $parsed->isExpired($now)) {
            return null;
        }
        $valid = $this->config->validator()->validate(
            $parsed,
            new SignedWith($this->config->signer(), $this->config->signingKey()),
            new PermittedFor('catalog-preview'),
        );

        return $valid ? $parsed->claims()->get('sub') : null;
    }
}
