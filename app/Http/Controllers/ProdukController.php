<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\Produk;
use Illuminate\Http\Request;

class ProdukController extends Controller
{
    /**
     * Display a listing of all products.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function index()
    {
        try {
            $produk = Produk::all();

            return response()->json([
                'success' => true,
                'message' => 'Data produk berhasil diambil',
                'data' => $produk
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil data produk',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Display products by category.
     *
     * @param string $kategori
     * @return \Illuminate\Http\JsonResponse
     */
    public function getByKategori($kategori)
    {
        try {
            $produk = Produk::where('kategori', $kategori)->get();

            if ($produk->isEmpty()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tidak ada produk dalam kategori ' . $kategori,
                    'data' => []
                ], 404);
            }

            return response()->json([
                'success' => true,
                'message' => 'Data produk kategori ' . $kategori . ' berhasil diambil',
                'data' => $produk
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil data produk',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Get all unique categories.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function getKategori()
    {
        try {
            $kategori = Produk::select('kategori')
                ->distinct()
                ->pluck('kategori');

            return response()->json([
                'success' => true,
                'message' => 'Data kategori berhasil diambil',
                'data' => $kategori
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil data kategori',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Display the specified product.
     *
     * @param int $id
     * @return \Illuminate\Http\JsonResponse
     */
    public function show($id)
    {
        try {
            $produk = Produk::find($id);

            if (!$produk) {
                return response()->json([
                    'success' => false,
                    'message' => 'Produk tidak ditemukan',
                    'data' => null
                ], 404);
            }

            return response()->json([
                'success' => true,
                'message' => 'Data produk berhasil diambil',
                'data' => $produk
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Gagal mengambil data produk',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}
