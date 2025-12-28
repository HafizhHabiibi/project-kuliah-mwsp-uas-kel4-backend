<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - BijiCoffeeShop</title>
    <style>
        /* Reset default browser styles */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(to right, #4a3750, #6b4c7a);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .container {
            background: #fff;
            padding: 40px 30px;
            border-radius: 12px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }

        h2 {
            text-align: center;
            color: #4a3750;
            margin-bottom: 20px;
        }

        p {
            text-align: center;
            color: #555;
            margin-bottom: 30px;
            font-size: 14px;
        }

        form input[type="email"],
        form input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            margin-bottom: 20px;
            border: 1px solid #ccc;
            border-radius: 8px;
            font-size: 14px;
        }

        form button {
            width: 100%;
            padding: 12px;
            background-color: #4a3750;
            color: #fff;
            font-size: 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        form button:hover {
            background-color: #6b4c7a;
        }

        .note {
            text-align: center;
            margin-top: 15px;
            font-size: 13px;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Reset Password</h2>
        <p>Masukkan password baru untuk akun Anda.</p>
        <form method="POST" action="{{ url('/api/reset-password') }}">
            @csrf
            <input type="hidden" name="token" value="{{ $token }}">
            <input type="email" name="email" value="{{ $email }}" readonly>
            <input type="password" name="password" placeholder="New Password" required>
            <input type="password" name="password_confirmation" placeholder="Confirm Password" required>
            <button type="submit">Reset Password</button>
        </form>
        <div class="note">
            Jika Anda tidak meminta reset password, abaikan halaman ini.
        </div>
    </div>
</body>
</html>
