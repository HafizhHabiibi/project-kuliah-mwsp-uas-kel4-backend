<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Chat;
use App\Models\Message;
use App\Models\Courier;

class ChatController extends Controller
{
    /**
     * GET /api/chats
     * Menampilkan list chat.
     * Jika user pertama kali membuka DM, sistem otomatis:
     * - Membuat chat untuk setiap courier
     * - Mengirim pesan pembuka dari courier
     */
    public function index(Request $request)
    {
        $user = $request->user();

        // Ambil semua courier
        $couriers = Courier::all();

        foreach ($couriers as $courier) {

            // Pastikan chat user + courier ADA
            $chat = Chat::firstOrCreate(
                [
                    'user_id'    => $user->id,
                    'courier_id' => $courier->id,
                ]
            );

            // Jika chat BARU dibuat → kirim pesan pembuka
            if ($chat->wasRecentlyCreated) {
                Message::create([
                    'chat_id' => $chat->id,
                    'sender'  => 'courier',
                    'message' => 'Halo 👋 Saya '.$courier->name.
                                 ', siap membantu pesanan Anda ☕',
                ]);
            }
        }

        // Ambil semua chat milik user
        $chats = Chat::with([
                'courier',
                'lastMessage'
            ])
            ->where('user_id', $user->id)
            ->orderByDesc(
                Message::select('created_at')
                    ->whereColumn('chat_id', 'chats.id')
                    ->latest()
                    ->limit(1)
            )
            ->get();

        return response()->json([
            'status' => 'success',
            'data'   => $chats,
        ]);
    }

    /**
     * GET /api/chats/{id}
     * Menampilkan isi pesan dalam chat
     */
    public function show($id, Request $request)
    {
        $chat = Chat::with('messages')->findOrFail($id);

        // Security: user hanya boleh akses chat miliknya
        if ($chat->user_id !== $request->user()->id) {
            abort(403, 'Unauthorized');
        }

        return response()->json([
            'status' => 'success',
            'data'   => [
                'chat_id'  => $chat->id,
                'messages' => $chat->messages,
            ],
        ]);
    }
}
