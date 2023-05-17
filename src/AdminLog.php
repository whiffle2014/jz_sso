<?php


namespace kizon;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Illuminate\Validation\UnauthorizedException;

class AdminLog
{

    protected static $redisKey = 'queue_log_list';
    public function handle(Request $request, Closure $next)
    {

        return $next($request);
    }

    public function terminate($request, $response)
    {
        $user =  $request->user();
        $path = $request->path();  //操作的路由

        $no_log_routers = config('logconfig.no_log_routers') ?? [];
        if (in_array($path, $no_log_routers)) {
            return;
        }
        if (!$request->isMethod('get') && $user) {
            self::writeLog($request, $response);
        }
    }
    public static function writeLog($request, $response)
    {
        $user =  $request->user();
        $arr = [
            'admin_id' => $user->id,
            'admin_account' => $user->account,
            'admin_name' => $user->name,
            'path' => $request->path(),
            'name' =>     $request->route()[1]['name'] ?? '',
            'method' => $request->method(),
            'ip' => $request->ip(),
            'request' => $request->all(),
            'response' => is_string($response->getOriginalContent()) ? json_decode($response->getOriginalContent(), true) : $response->getOriginalContent(),
            'status' => $response->status(),
            'created_at' => Date('Y-m-d H:i:s'),
            'sys' => config('app.sys'),
        ];

        // JSON_UNESCAPED_UNICODE
        Redis::rPush(config('logconfig.redis_log_key'), json_encode($arr, JSON_UNESCAPED_UNICODE));
    }
}
