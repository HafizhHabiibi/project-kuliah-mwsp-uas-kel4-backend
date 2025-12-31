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
            // Beverages Category
            [
                'nama' => 'Fresh Orange Juice',
                'gambar_url' => 'https://keeshaskitchen.com/wp-content/uploads/2022/10/Fresh-Made-Orange-Juice.jpg',
                'kategori' => 'Beverages',
                'harga' => 3.99,
                'deskripsi' => 'Freshly squeezed orange juice packed with vitamin C. Perfect for a healthy start to your day.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Iced Latte',
                'gambar_url' => 'https://www.acouplecooks.com/wp-content/uploads/2021/08/Iced-Latte-003.jpg',
                'kategori' => 'Beverages',
                'harga' => 6.49,
                'deskripsi' => 'Smooth espresso mixed with cold milk and ice. A refreshing coffee experience.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Green Tea Lemonade',
                'gambar_url' => 'https://st2.depositphotos.com/1692343/7179/i/450/depositphotos_71796819-stock-photo-homemade-iced-tea-and-lemonade.jpg', // edit gambar
                'kategori' => 'Beverages',
                'harga' => 5.49,
                'deskripsi' => 'A perfect blend of green tea and fresh lemon. Healthy and refreshing.',
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Food Category
            [
                'nama' => 'Grilled Chicken Salad',
                'gambar_url' => 'https://cookingformysoul.com/wp-content/uploads/2019/01/grilled-chicken-salad-min.jpg',
                'kategori' => 'Food',
                'harga' => 10.99,
                'deskripsi' => 'Fresh mixed greens with grilled chicken breast, cherry tomatoes, and balsamic dressing.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Spaghetti Carbonara',
                'gambar_url' => 'https://www.twopeasandtheirpod.com/wp-content/uploads/2023/01/Spaghetti-Carbonara168787.jpg',
                'kategori' => 'Food',
                'harga' => 13.99,
                'deskripsi' => 'Classic Italian pasta with creamy sauce, bacon, and parmesan cheese.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Fish and Chips',
                'gambar_url' => 'https://wallpapers.com/images/file/perfectly-fried-fish-and-chips-1qfc430mwbqnmqy3.jpg',
                'kategori' => 'Food',
                'harga' => 11.49,
                'deskripsi' => 'Crispy battered fish served with golden fries and tartar sauce.',
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Pizza Category
            [
                'nama' => 'Margherita Pizza',
                'gambar_url' => 'https://ohsweetbasil.com/wp-content/uploads/how-to-make-authentic-margherita-pizza-at-home-recipe-4.jpg',
                'kategori' => 'Pizza',
                'harga' => 14.99,
                'deskripsi' => 'Classic Italian pizza with fresh mozzarella, tomato sauce, and basil leaves.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Pepperoni Pizza',
                'gambar_url' => 'https://static.vecteezy.com/system/resources/previews/029/563/152/non_2x/pepperoni-pizza-isolated-free-photo.jpg',
                'kategori' => 'Pizza',
                'harga' => 16.99,
                'deskripsi' => 'Loaded with pepperoni slices, mozzarella cheese, and our signature tomato sauce.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'BBQ Chicken Pizza',
                'gambar_url' => 'https://www.nutmegnanny.com/wp-content/uploads/2023/01/bbq-chicken-pizza-2.jpg',
                'kategori' => 'Pizza',
                'harga' => 17.99,
                'deskripsi' => 'Grilled chicken with BBQ sauce, red onions, and cilantro on a crispy crust.',
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Drink Category
            [
                'nama' => 'Mango Smoothie',
                'gambar_url' => 'https://www.eatingbirdfood.com/wp-content/uploads/2021/05/mango-smoothie-angle-1024x1536.jpg',
                'kategori' => 'drink',
                'harga' => 5.99,
                'deskripsi' => 'Creamy mango smoothie made with fresh mangoes and yogurt. Tropical delight!',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Iced Chocolate',
                'gambar_url' => 'https://www.shutterstock.com/image-photo/close-glass-iced-cocoa-cool-260nw-1061011808.jpg', // edit gambar
                'kategori' => 'drink',
                'harga' => 5.49,
                'deskripsi' => 'Rich chocolate drink served cold with whipped cream topping.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Strawberry Milkshake',
                'gambar_url' => 'https://www.unicornsinthekitchen.com/wp-content/uploads/2021/07/Strawberry-Milkshake-2.1200px-1-of-1.jpg',
                'kategori' => 'drink',
                'harga' => 6.49,
                'deskripsi' => 'Thick and creamy strawberry milkshake topped with fresh strawberries.',
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Launch Category (Lunch items)
            [
                'nama' => 'Chicken Teriyaki Bowl',
                'gambar_url' => 'https://www.wholesomeyum.com/wp-content/uploads/2023/05/wholesomeyum-Teriyaki-Chicken-Bowl-5.jpg',
                'kategori' => 'launch',
                'harga' => 10.49,
                'deskripsi' => 'Grilled chicken with teriyaki sauce served over steamed rice with vegetables.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Beef Steak Set',
                'gambar_url' => 'https://cdn.pixabay.com/photo/2017/04/30/09/30/steak-2272464_1280.jpg',
                'kategori' => 'launch',
                'harga' => 19.99,
                'deskripsi' => 'Tender beef steak with mashed potatoes, grilled vegetables, and black pepper sauce.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Salmon Fillet Lunch',
                'gambar_url' => 'https://thumbs.dreamstime.com/b/grilled-salmon-fillet-fresh-vegetable-salad-gourmet-lunch-generated-ai-artificial-intelligence-277565607.jpg',
                'kategori' => 'launch',
                'harga' => 22.99,
                'deskripsi' => 'Pan-seared salmon with lemon butter sauce, asparagus, and quinoa.',
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Burger Category
            [
                'nama' => 'Classic Beef Burger',
                'gambar_url' => 'https://cdn.pixabay.com/photo/2022/07/15/18/16/beef-burger-7323692_1280.jpg',
                'kategori' => 'burger',
                'harga' => 10.99,
                'deskripsi' => 'Juicy beef patty with lettuce, tomato, onions, pickles, and our special sauce.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Cheese Burger Deluxe',
                'gambar_url' => 'https://static.vecteezy.com/system/resources/thumbnails/045/607/037/small/delicious-cheeseburger-close-up-photo.jpg', // edit gambar
                'kategori' => 'burger',
                'harga' => 13.99,
                'deskripsi' => 'Double beef patty with melted cheddar cheese, bacon, and caramelized onions.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Chicken Burger',
                'gambar_url' => 'https://t3.ftcdn.net/jpg/00/40/24/60/360_F_40246031_zWZoDrKKr4jusGNtSpKV7Zvy9VdeIi88.jpg', // edit gambar
                'kategori' => 'burger',
                'harga' => 10.49,
                'deskripsi' => 'Crispy fried chicken breast with coleslaw and mayo in a soft bun.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'nama' => 'Mushroom Swiss Burger',
                'gambar_url' => 'https://www.emilyenchanted.com/wp-content/uploads/2023/02/Mushroom-Swiss-Burger-Featured-Image-1024x1024.jpg',
                'kategori' => 'burger',
                'harga' => 11.49,
                'deskripsi' => 'Beef patty topped with sautéed mushrooms and melted Swiss cheese.',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ];
        DB::table('produk')->insert($produk);
    }
}
