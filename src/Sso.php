<?php


namespace kizon;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\URL;
use mysql_xdevapi\Table;

class Sso
{
    public function handle(Request $request, Closure $next, $permission = null)
    {
        try {
            //获取token
            $request = request();
            $header = $request->header('Authorization', '');

            if (empty($header)) {
                return response()->json(['data' => [], 'code' => "00002", 'message' => "token is not defind", 'status' => 'failed'], '401');
            }
            if (!preg_match('/[Bearer|bearer]\\s(\\S+)/', $header, $matches)) {
                return response()->json(['data' => [], 'code' => "00005", 'message' => "token is not defind", 'status' => 'failed'], '401');
            }
            $token = $matches[1];
            if (empty($token)) {
                return response()->json(['data' => [], 'code' => "00006", 'message' => "token is not defind", 'status' => 'failed'], '401');
            }

            //获取域名判断当前系统--占位
            $domain = 'http://' . $_SERVER['HTTP_HOST'];
            $systemPrefix = DB::connection("auth_mysql")->table("domain")->where("name", $domain)->where("status", 1)->first();
            if (empty($systemPrefix)) {
                return response()->json(['data' => [], 'code' => "00003", 'message' => "domain is not defind", 'status' => 'failed'], '401');
            }
            //拼接权限名称--系统前缀+路由
            if (empty($systemPrefix->route_prefix)) {
                return response()->json(['data' => [], 'code' => "00004", 'message' => "route_prefix is not defind", 'status' => 'failed'], '401');
            }
            $routName = str_replace('/', '-', str_replace($systemPrefix->route_prefix . '/', '', $request->path()));
            if (empty($routName)) {
                return response()->json(['data' => [], 'code' => "00001", 'message' => "authenticate is error", 'status' => 'failed'], '401');
            }

            //权限名称: 系统前缀 + 路由名称
            $authPostData['permission'] = $systemPrefix->system_prefix . '-' . $routName;
            $curldata = $this->send(config('app.auth_url') . '/api/auth', $token, json_encode($authPostData));

            if ($curldata['code'] != '200') {
                return response()->json($curldata['data'], $curldata['code']);
            }

            if ($curldata['data']['status'] === 'success' && $curldata['data']['code'] === 200) {
                return $next($request);
            } else {
                return $curldata['data'];
            }
        } catch (\Exception $e) {

            Log::info('认证错误!', ['error_msg' => $e->getMessage(), 'error_info' => $e->getTraceAsString()]);
            return response()->json(['data' => [], 'code' => "401", 'message' => "authenticate is error", 'status' => 'failed'], '401');
        }
    }

    private function send($url, $token, $authPostData)
    {
        $header = array(
            'Content-Type: application/json',
            'Accept-Charset: UTF-8',
            'Authorization: bearer ' . $token,
        );

        //初始化
        $curl = curl_init();
        //设置抓取的url
        curl_setopt($curl, CURLOPT_URL, $url);
        //设置头文件的信息作为数据流输出
        curl_setopt($curl, CURLOPT_HEADER, 0);
        //设置获取的信息以文件流的形式返回，而不是直接输出。
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        // 超时设置
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);

        // 超时设置，以毫秒为单位
        // curl_setopt($curl, CURLOPT_TIMEOUT_MS, 500);

        // 设置请求头
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);

        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);

        //设置post方式提交
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $authPostData);
        //执行命令
        $data = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        // 显示错误信息
        if (curl_error($curl)) {
            print "Error: " . curl_error($curl);
        } else {
            // 打印返回的内容
            curl_close($curl);
        }

        return ['data' => json_decode($data, true), 'code' => $httpCode];
    }
}
