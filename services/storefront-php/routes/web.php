<?php

declare(strict_types=1);

use App\Http\Controllers\CheckoutController;
use App\Http\Controllers\GiftCardController;
use App\Http\Controllers\OrderHistoryController;
use App\Http\Middleware\AddCatalogETag;
use App\Http\Middleware\IdempotencyKeys;
use Illuminate\Routing\Router;

/** @var Router $router */
$router->middleware([IdempotencyKeys::class])->group(function (Router $router): void {
    $router->post('/checkout', [CheckoutController::class, 'placeOrder']);
    $router->post('/orders/{reference}/cancel', [OrderHistoryController::class, 'cancel']);
});

$router->get('/checkout/experiment', [CheckoutController::class, 'experiment']);
$router->get('/orders', [OrderHistoryController::class, 'index']);
$router->get('/orders/{reference}', [OrderHistoryController::class, 'show']);

$router->post('/gift-cards/balance', [GiftCardController::class, 'balance']);
$router->post('/gift-cards/pin', [GiftCardController::class, 'setPin']);

$router->middleware([AddCatalogETag::class])->group(function (Router $router): void {
    $router->get('/catalog/{merchant}', fn (string $merchant) => ['merchant' => $merchant]);
    $router->get('/catalog/{merchant}/{sku}', fn (string $merchant, string $sku) => ['merchant' => $merchant, 'sku' => $sku]);
});
