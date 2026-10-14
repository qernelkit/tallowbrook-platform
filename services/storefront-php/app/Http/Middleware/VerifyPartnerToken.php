<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Support\Config;
use Closure;
use DomainException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use UnexpectedValueException;

/**
 * Payment partners call the settlement API with a bearer token we issue them out of band.
 */
final class VerifyPartnerToken
{
    public function __construct(private readonly string $partnerSecret)
    {
    }

    public static function fromConfig(): self
    {
        return new self((string) Config::get('services.partners.bearer_secret', ''));
    }

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();
        if ($bearer === null || $bearer === '') {
            return new JsonResponse(['error' => 'missing bearer token'], 401);
        }

        try {
            $claims = JWT::decode($bearer, new Key($this->partnerSecret, 'HS256'));
        } catch (ExpiredException) {
            return new JsonResponse(['error' => 'token expired'], 401);
        } catch (UnexpectedValueException|DomainException) {
            return new JsonResponse(['error' => 'invalid token'], 401);
        }

        if (!isset($claims->sub) || !is_string($claims->sub)) {
            return new JsonResponse(['error' => 'token has no subject'], 401);
        }
        $request->attributes->set('partner_id', $claims->sub);

        return $next($request);
    }
}
