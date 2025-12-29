<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\Keranjang;
use App\Models\Produk;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class KeranjangController extends Controller
{
    /**
     * Display the authenticated user's cart.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function index()
    {
        try {
            $user = Auth::user();

            // Get cart items with product details
            $keranjang = Keranjang::where('user_id', $user->id)
                ->with('produk')
                ->get();

            // Calculate subtotal for each item and total
            $cartItems = $keranjang->map(function ($item) {
                return [
                    'id' => $item->id,
                    'produk_id' => $item->produk_id,
                    'nama' => $item->produk->nama,
                    'gambar_url' => $item->produk->gambar_url,
                    'kategori' => $item->produk->kategori,
                    'harga' => $item->produk->harga,
                    'size' => $item->size,
                    'jumlah' => $item->jumlah,
                    'status' => $item->status,
                    'subtotal' => $item->produk->harga * $item->jumlah,
                ];
            });

            $total = $cartItems->sum('subtotal');

            return response()->json([
                'success' => true,
                'message' => 'Data keranjang berhasil diambil',
                'data' => [
                    'items' => $cartItems,
                    'total' => $total,
                    'jumlah_item' => $cartItems->count(),
                ]
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil data keranjang',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Add product to cart (Place Order from product detail).
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function store(Request $request)
    {
        try {
            $request->validate([
                'produk_id' => 'required|exists:produk,id_produk',
                'size' => 'nullable|string|max:50',
                'jumlah' => 'nullable|integer|min:1',
                'status' => 'nullable|in:all,delivery,done',
            ]);

            $user = Auth::user();
            $produkId = $request->produk_id;
            $size = $request->size;
            $jumlah = $request->jumlah ?? 1;
            $status = $request->status ?? 'all';

            // Check if product exists
            $produk = Produk::where('id_produk', $produkId)->first();
            if (!$produk) {
                return response()->json([
                    'success' => false,
                    'message' => 'Produk tidak ditemukan',
                ], 404);
            }

            // Check if product already in cart with same size
            $existingCart = Keranjang::where('user_id', $user->id)
                ->where('produk_id', $produkId)
                ->where('size', $size)
                ->first();

            if ($existingCart) {
                // Update quantity if already exists
                $existingCart->jumlah += $jumlah;
                $existingCart->save();

                return response()->json([
                    'success' => true,
                    'message' => 'Jumlah produk di keranjang berhasil diperbarui',
                    'data' => $existingCart
                ], 200);
            } else {
                // Create new cart item
                $keranjang = Keranjang::create([
                    'user_id' => $user->id,
                    'produk_id' => $produkId,
                    'size' => $size,
                    'jumlah' => $jumlah,
                    'status' => $status,
                ]);

                return response()->json([
                    'success' => true,
                    'message' => 'Produk berhasil ditambahkan ke keranjang',
                    'data' => $keranjang
                ], 201);
            }
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Validasi gagal',
                'errors' => $e->errors()
            ], 422);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal menambahkan produk ke keranjang',
                'error' => $e->getMessage()
            ], 500);
        }
    }

     /**
     * Update the specified cart item.
     *
     * @param int $id
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function update($id, Request $request)
    {
        try {
            $keranjang = Keranjang::find($id);

            if (!$keranjang) {
                return response()->json([
                    'success' => false,
                    'message' => 'Keranjang tidak ditemukan',
                    'data' => null
                ], 404);
            }

            $keranjang->update($request->all());

            return response()->json([
                'success' => true,
                'message' => 'Keranjang berhasil diperbarui',
                'data' => $keranjang
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal memperbarui keranjang',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Remove the specified cart item.
     *
     * @param int $id
     * @return \Illuminate\Http\JsonResponse
     */
    public function destroy($id)
    {
        try {
            $keranjang = Keranjang::find($id);

            if (!$keranjang) {
                return response()->json([
                    'success' => false,
                    'message' => 'Keranjang tidak ditemukan',
                    'data' => null
                ], 404);
            }

            $keranjang->delete();

            return response()->json([
                'success' => true,
                'message' => 'Keranjang berhasil dihapus',
                'data' => $keranjang
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal menghapus keranjang',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}
