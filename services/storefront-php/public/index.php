<?php

declare(strict_types=1);

use App\Support\Config;
use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;

require __DIR__ . '/../vendor/autoload.php';

date_default_timezone_set((string) Config::get('app.timezone', 'UTC'));

$container = new Container();
$router = new Router(new Dispatcher($container), $container);

require __DIR__ . '/../routes/web.php';
require __DIR__ . '/../routes/api.php';

$response = $router->dispatch(Request::capture());
$response->send();
