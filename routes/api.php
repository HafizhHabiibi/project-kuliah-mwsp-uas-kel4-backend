<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthenticationController;
use App\Http\Controllers\API\ProductController;
use App\Http\Controllers\ProdukController;
use App\Http\Controllers\KeranjangController;

// --------------- Register & Login (PUBLIC) ----------------
Route::post('/register', [AuthenticationController::class, 'register']);
Route::post('/login', [AuthenticationController::class, 'login']);

// --------------- Forgot Password (PUBLIC) ----------------
Route::post('/forgot-password', [AuthenticationController::class, 'forgotPassword']);
Route::post('/reset-password', [AuthenticationController::class, 'resetPassword']);

// --------------- Produk Routes (PUBLIC) ----------------
Route::get('/produk', [ProdukController::class, 'index']); // Get all products
Route::get('/produk/kategori', [ProdukController::class, 'getKategori']); // Get all categories
Route::get('/produk/kategori/{kategori}', [ProdukController::class, 'getByKategori']); // Get products by category
Route::get('/produk/{id}', [ProdukController::class, 'show']); // Get product by ID

// --------------- Protected Routes (SANCTUM) ----------------
Route::middleware('auth:sanctum')->group(function () {

    // Auth
    Route::get('/get-user', [AuthenticationController::class, 'userInfo']);
    Route::post('/logout', [AuthenticationController::class, 'logOut']);

    // Profile Update
    Route::put('/user/profile', [AuthenticationController::class, 'updateProfile']);

    // Keranjang (Shopping Cart)
    Route::get('/keranjang', [KeranjangController::class, 'index']); // View cart
    Route::post('/keranjang', [KeranjangController::class, 'store']); // Add to cart (Place Order)
    Route::put('/keranjang/{id}', [KeranjangController::class, 'update']); // Update quantity
    Route::delete('/keranjang/{id}', [KeranjangController::class, 'destroy']); // Remove from cart

});
