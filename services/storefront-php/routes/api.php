<?php

declare(strict_types=1);

use App\Http\Controllers\LockerController;
use App\Http\Controllers\WebhookController;
use App\Http\Middleware\VerifyPartnerToken;
use Illuminate\Routing\Router;

/** @var Router $router */
$router->prefix('api/v1')->group(function (Router $router): void {
    $router->post('/lockers/{lockerId}/enrol', [LockerController::class, 'enrol']);
    $router->get('/lockers/{lockerId}', [LockerController::class, 'status']);

    $router->post('/webhooks/marketplace', [WebhookController::class, 'marketplace']);
    $router->post('/webhooks/partners/{partnerId}', [WebhookController::class, 'partner']);

    $router->middleware([VerifyPartnerToken::class])->group(function (Router $router): void {
        $router->get('/settlements', fn () => ['settlements' => []]);
        $router->get('/settlements/{id}', fn (string $id) => ['id' => $id]);
    });
});
