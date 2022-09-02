<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'  // password_confirmed
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

//        $token = $request->user()->createToken('my-laravel-api-token');
        $token = $user->createToken('my-laravel-api-token')->plainTextToken;

//        return ['token' => $token->plainTextToken];
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function logout(Request $request) {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Logged Out'
        ];
    }


    public function login(Request $request) {
        $fields = $request->validate([
//            'email' => 'required|string|exists:users,email',
            'email' => 'required|string',
            'password' => 'required|string'  // password_confirmed
        ]);

        $user = User::where('email', $fields['email'])->first();

        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'message' => 'The Credentials Not True'
            ], 401);
        }

        $token = $user->createToken('my-laravel-api-token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);

    }
}
