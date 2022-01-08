<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(Request $request){
        $validated_data = $request->validate([
            'name' => 'required',
            'email' => 'email | required | unique:users',
            'phone' => 'required',
            'password' => 'required | confirmed'
        ]);

        $validated_data['password'] = bcrypt($validated_data['password']);
        $validated_data['uuid'] = Str::uuid();
        $user = User::create($validated_data);
        $access_token = $user->createToken('authToken')->accessToken;
        //return returnUserResponse(true, 'User registered successfully', $user, $access_token, 200);
        return response()->json(['status' => true, 'message' => 'User registered successfully', 'data' => $user, 'access_token' => $access_token], 200);
    }

    public function login(Request $request){
        $login_data = $request->validate([
            'email' => 'required | email',
            'password' => 'required'
        ]);
        if(!auth()->attempt($login_data)){
            return response()->json(['status' => false, 'message' => 'Error logging in'], 400);
        }
        $user = auth()->user();
        $access_token = $user->createToken('authToken')->accessToken;
        return response()->json(['status' => true, 'message' => 'User logged in successfully', 'data' => $user, 'access_token' => $access_token], 200);
    }

}
