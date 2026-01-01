<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Courier;

class CourierSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Courier::insert([
            [
                'name' => 'Sam Verdinand',
                'avatar' => 'avatars/1.jpg',
                'is_online' => true,
            ],
            [
                'name' => 'Freddie Ronan',
                'avatar' => 'avatars/2.jpg',
                'is_online' => true,
            ],
            [
                'name' => 'Ethan Jacoby',
                'avatar' => 'avatars/3.jpg',
                'is_online' => true,
            ],
            [
                'name' => 'Alfie Mason',
                'avatar' => 'avatars/4.jpg',
                'is_online' => true,
            ],
            [
                'name' => 'Archie Parker',
                'avatar' => 'avatars/5.jpg',
                'is_online' => true,
            ],
        ]);
    }
}
