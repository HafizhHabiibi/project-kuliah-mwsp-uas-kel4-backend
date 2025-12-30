<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use App\Models\Produk;

class Wishlist extends Model
{
    protected $table = 'wishlist'; // optional tapi aman

    protected $fillable = [
        'user_id',
        'produk_id',
    ];

    /**
     * Relasi ke tabel produk
     */
    public function product()
    {
        return $this->belongsTo(Produk::class, 'produk_id', 'id_produk');
    }
}
