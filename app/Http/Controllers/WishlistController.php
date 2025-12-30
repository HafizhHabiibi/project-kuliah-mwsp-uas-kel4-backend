<?php

namespace App\Http\Controllers;

use App\Models\Wishlist;
use Illuminate\Http\Request;

class WishlistController extends Controller
{
    /**
     * GET /wishlist
     * Mengambil semua wishlist milik user yang sedang login
     */
    public function index(Request $request)
    {
        $wishlist = Wishlist::with('product')
            ->where('user_id', $request->user()->id)
            ->get();

        // Format response sesuai Flutter: setiap item memiliki key 'product'
        $data = $wishlist->map(fn($w) => ['product' => $w->product]);

        return response()->json([
            'success' => true,
            'data'    => $data,
        ], 200);
    }

    /**
     * POST /wishlist
     * Menambahkan produk ke wishlist
     */
    public function store(Request $request)
    {
        $request->validate([
            // Pastikan validator sesuai nama tabel dan kolom
            'produk_id' => 'required|exists:produk,id_produk',
        ]);

        // Buat wishlist baru jika belum ada
        $wishlist = Wishlist::firstOrCreate([
            'user_id'   => $request->user()->id,
            'produk_id' => $request->produk_id,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Added to wishlist',
            'data'    => ['product' => $wishlist->product],
        ], 201);
    }

    /**
     * DELETE /wishlist/{produk_id}
     * Menghapus produk dari wishlist
     */
    public function destroy(Request $request, $produk_id)
    {
        $deleted = Wishlist::where('user_id', $request->user()->id)
            ->where('produk_id', $produk_id)
            ->delete();

        if ($deleted) {
            return response()->json([
                'success' => true,
                'message' => 'Removed from wishlist',
            ], 200);
        }

        return response()->json([
            'success' => false,
            'message' => 'Produk tidak ditemukan di wishlist',
        ], 404);
    }
}
