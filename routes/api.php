<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthenticationController;
use App\Http\Controllers\API\ProductController;

// --------------- Register & Login (PUBLIC) ----------------
Route::post('/register', [AuthenticationController::class, 'register']);
Route::post('/login', [AuthenticationController::class, 'login']);

// --------------- Forgot Password (PUBLIC) ----------------
Route::post('/forgot-password', [AuthenticationController::class, 'forgotPassword']);
Route::post('/reset-password', [AuthenticationController::class, 'resetPassword']);

// --------------- Protected Routes (SANCTUM) ----------------
Route::middleware('auth:sanctum')->group(function () {

    // Auth
    Route::get('/get-user', [AuthenticationController::class, 'userInfo']);
    Route::post('/logout', [AuthenticationController::class, 'logOut']);
    
    // Profile Update
    Route::put('/user/profile', [AuthenticationController::class, 'updateProfile']);

});
