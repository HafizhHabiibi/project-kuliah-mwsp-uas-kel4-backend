<?php
namespace Database\Seeders;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
class ProdukSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $produk = [
            [
                'nama' => 'Nasi Goreng Spesial',
                'gambar_url' => 'https://images.unsplash.com/photo-1512058564366-18510be2db19',
                'kategori' => 'Makanan',
                'harga' => 25000,
                'deskripsi' => 'Nasi goreng dengan telur, ayam, dan sayuran segar. Dilengkapi dengan kerupuk dan acar.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Mie Goreng Seafood',
                'gambar_url' => 'https://images.unsplash.com/photo-1585032226651-759b368d7246',
                'kategori' => 'Makanan',
                'harga' => 30000,
                'deskripsi' => 'Mie goreng dengan udang, cumi, dan sayuran. Rasa gurih dan pedas yang menggugah selera.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Es Teh Manis',
                'gambar_url' => 'https://images.unsplash.com/photo-1556679343-c7306c1976bc',
                'kategori' => 'Minuman',
                'harga' => 5000,
                'deskripsi' => 'Teh manis dingin yang menyegarkan, cocok untuk menemani makanan Anda.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Jus Alpukat',
                'gambar_url' => 'https://images.unsplash.com/photo-1623065422902-30a2d299bbe4',
                'kategori' => 'Minuman',
                'harga' => 15000,
                'deskripsi' => 'Jus alpukat segar dengan susu dan gula aren. Creamy dan lezat.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Ayam Geprek',
                'gambar_url' => 'https://images.unsplash.com/photo-1604908176997-125f25cc6f3d',
                'kategori' => 'Makanan',
                'harga' => 20000,
                'deskripsi' => 'Ayam goreng crispy yang digeprek dengan sambal pedas. Tersedia level kepedasan 1-5.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Sate Ayam',
                'gambar_url' => 'https://images.unsplash.com/photo-1529563021893-cc83c992d75d',
                'kategori' => 'Makanan',
                'harga' => 28000,
                'deskripsi' => 'Sate ayam dengan bumbu kacang khas. 10 tusuk per porsi dengan lontong dan acar.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Kopi Susu Gula Aren',
                'gambar_url' => 'https://images.unsplash.com/photo-1517487881594-2787fef5ebf7',
                'kategori' => 'Minuman',
                'harga' => 18000,
                'deskripsi' => 'Kopi susu dengan gula aren asli. Manis alami dan tidak terlalu pahit.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Bakso Urat',
                'gambar_url' => 'https://images.unsplash.com/photo-1586190848861-99aa4a171e90',
                'kategori' => 'Makanan',
                'harga' => 22000,
                'deskripsi' => 'Bakso urat dengan kuah kaldu sapi yang gurih. Dilengkapi mie, tahu, dan sayuran.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Pisang Goreng',
                'gambar_url' => 'https://asset.kompas.com/crops/eABDv6XX5_YQPkqFA7gVfmtXq6E=/0x0:1056x704/1200x800/data/photo/2025/09/24/68d37921c8b99.jpg',
                'kategori' => 'Snack',
                'harga' => 10000,
                'deskripsi' => 'Pisang goreng crispy dengan taburan keju dan coklat. 5 potong per porsi.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Kentang Goreng',
                'gambar_url' => 'https://images.unsplash.com/photo-1573080496219-bb080dd4f877',
                'kategori' => 'Snack',
                'harga' => 12000,
                'deskripsi' => 'Kentang goreng renyah dengan saus sambal dan mayonaise.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Es Jeruk',
                'gambar_url' => 'https://images.unsplash.com/photo-1600271886742-f049cd451bba',
                'kategori' => 'Minuman',
                'harga' => 8000,
                'deskripsi' => 'Jus jeruk segar dengan es batu. Asam manis yang menyegarkan.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Nasi Uduk',
                'gambar_url' => 'https://images.unsplash.com/photo-1596797038530-2c107229654b',
                'kategori' => 'Makanan',
                'harga' => 18000,
                'deskripsi' => 'Nasi uduk dengan lauk ayam goreng, telur balado, dan sambal kacang.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Cappuccino',
                'gambar_url' => 'https://images.unsplash.com/photo-1572442388796-11668a67e53d',
                'kategori' => 'Minuman',
                'harga' => 20000,
                'deskripsi' => 'Cappuccino dengan foam susu yang lembut dan latte art cantik.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Roti Bakar Coklat Keju',
                'gambar_url' => 'https://images.unsplash.com/photo-1509440159596-0249088772ff',
                'kategori' => 'Snack',
                'harga' => 15000,
                'deskripsi' => 'Roti bakar dengan topping coklat dan keju yang melimpah.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Soto Ayam',
                'gambar_url' => 'https://images.unsplash.com/photo-1604908176997-125f25cc6f3d',
                'kategori' => 'Makanan',
                'harga' => 23000,
                'deskripsi' => 'Soto ayam dengan kuah kuning yang gurih. Dilengkapi dengan nasi, telur, dan kerupuk.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ];
        DB::table('produk')->insert($produk);
    }
}
