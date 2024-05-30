<?php

namespace App\Http\Controllers;

use App\Models\User;
use Validator;


class AuthController extends Controller
{
    public function getList()
    {
        $user = new User();
        if(request()->has('filter') && is_array(request()->get('filter'))){
            $user = filterParam($user,request()->get('filter'));
        }


        if(request()->has('with') && is_array(request()->get('with'))){
            foreach (request()->get('with') as $s)
                $user = $user->with($s);
        }

        return response()->json($user->where('user_code',auth('api')->user()->user_code)->first());
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register() {
        try {
            $validator = Validator::make(request()->all(), [
                'first_name' => 'required',
                'last_name' => 'required',
                'email' => 'required|email|unique:users',
                'password' => 'required|confirmed|min:6',
            ]);

            if($validator->fails()){
                return response()->json($validator->errors(), 400);
            }

            $user = new User;
            $user->first_name = request()->first_name;
            $user->last_name = request()->last_name;
            $user->user_code = uuid();
            $user->email = request()->email;
            $user->user_level = request()->get("user_level",0);
            $user->password = bcrypt(request()->password);
            $user->save();

            return response()->json($user, 201);
        }catch (\Exception $e){
            return response()->json([
                "error"=>[
                    "message"=>$e->getMessage()
                ]
            ], 500);
        }
    }


    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth('api')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }
}
