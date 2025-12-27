<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use App\Models\User;

class AuthenticationController extends Controller
{
    /**
     * Register user
     */
    public function register(Request $request)
    {
        $validated = $request->validate([
            'name'     => 'required|string|min:4',
            'email'    => 'required|email|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name'     => $validated['name'],
            'email'    => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'user'   => $user,
            'token'  => $token,
        ], 201);
    }

    /**
     * Login user
     */
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email'    => 'required|email',
            'password' => 'required|string',
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'status'  => 'error',
                'message' => 'Invalid credentials',
            ], 401);
        }

        $user  = Auth::user();
        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'user'   => $user,
            'token'  => $token,
        ]);
    }

    /**
     * GET CURRENT LOGGED-IN USER
     */
    public function userInfo(Request $request)
    {
        return response()->json([
            'status' => 'success',
            'data'   => $request->user(), 
        ]);
    }

    /**
     * Update profile user
     */
    public function updateProfile(Request $request)
    {
        $user = $request->user();

        $validated = $request->validate([
            'name'              => 'sometimes|string|min:4',
            'address'           => 'nullable|string|max:500',
            'profile_photo_url' => 'nullable|url',
        ]);

        $user->update($validated);

        return response()->json([
            'status' => 'success',
            'user'   => $user,
        ]);
    }

    /**
     * Logout
     */
    public function logOut(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json([
            'status'  => 'success',
            'message' => 'Logged out',
        ]);
    }
}