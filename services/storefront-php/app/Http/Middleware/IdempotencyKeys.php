<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Services\Orders\IdempotencyStore;
use App\Services\Orders\StoredResponse;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Replays the stored response when a client retries a POST with the same Idempotency-Key,
 * so a flaky mobile connection never places an order twice.
 */
final class IdempotencyKeys
{
    public function __construct(private readonly IdempotencyStore $store)
    {
    }

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $key = $request->header('Idempotency-Key');
        if (!$request->isMethod('POST') || !is_string($key) || $key === '') {
            return $next($request);
        }
        if (strlen($key) > 128) {
            return new JsonResponse(['error' => 'Idempotency-Key is too long'], 400);
        }

        $bodyHash = hash('sha256', $request->getContent());
        $snapshot = base64_encode(json_encode($request->headers->all(), JSON_THROW_ON_ERROR));

        $previous = $this->store->find($key);
        if ($previous !== null) {
            if ($previous->bodyHash !== $bodyHash) {
                return new JsonResponse(['error' => 'Idempotency-Key was used with a different request body'], 422);
            }

            return new Response($previous->body, $previous->status, ['Content-Type' => 'application/json', 'Idempotent-Replayed' => 'true']);
        }

        $response = $next($request);
        if ($response->getStatusCode() < 500) {
            $this->store->save($key, new StoredResponse($bodyHash, $response->getStatusCode(), (string) $response->getContent(), $snapshot));
        }

        return $response;
    }
}
