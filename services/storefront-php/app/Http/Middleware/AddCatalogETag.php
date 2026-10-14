<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Adds an ETag to catalogue pages so browsers and the CDN can revalidate cheaply, and tags
 * the response with the cache shard that holds the product.
 */
final class AddCatalogETag
{
    private const SHARDS = 16;

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (!$request->isMethod('GET') || $response->getStatusCode() !== 200) {
            return $response;
        }

        $sku = (string) $request->query('sku', '');
        $etag = '"' . md5((string) $response->getContent()) . '"';
        $response->headers->set('ETag', $etag);
        $response->headers->set('X-Cache-Shard', (string) (crc32($sku) % self::SHARDS));
        $response->headers->set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');

        if ($request->headers->get('If-None-Match') === $etag) {
            $response->setNotModified();
        }

        return $response;
    }
}
