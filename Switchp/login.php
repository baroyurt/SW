<?php
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);

/**
 * Validate a return URL: must be a valid URL, same host, and http/https scheme only.
 */
function isSafeReturnUrl(string $url): bool {
    if (!filter_var($url, FILTER_VALIDATE_URL)) return false;
    $scheme = strtolower(parse_url($url, PHP_URL_SCHEME) ?? '');
    if (!in_array($scheme, ['http', 'https'], true)) return false;
    if (parse_url($url, PHP_URL_HOST) !== $_SERVER['HTTP_HOST']) return false;
    return true;
}

// Redirect if already logged in
if ($auth->isLoggedIn()) {
    $return = $_GET['return'] ?? '';
    if ($return && isSafeReturnUrl($return)) {
        header('Location: ' . $return);
    } elseif ($auth->isAdmin()) {
        header('Location: pages/company_select.php');
    } else {
        header('Location: index.php');
    }
    exit;
}

$error = '';
$success = '';
$returnUrl = '';
if (isset($_GET['return'])) {
    $candidate = $_GET['return'];
    if (isSafeReturnUrl($candidate)) {
        $returnUrl = $candidate;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $returnUrl = $_POST['return_url'] ?? '';
    // Re-validate (defence in depth)
    if ($returnUrl && !isSafeReturnUrl($returnUrl)) {
        $returnUrl = '';
    }
    
    if (empty($username) || empty($password)) {
        $error = 'Kullanıcı adı ve şifre gereklidir';
    } else {
        $result = $auth->login($username, $password);
        if ($result['success']) {
            if ($returnUrl) {
                header('Location: ' . $returnUrl);
            } elseif ($auth->isAdmin()) {
                header('Location: pages/company_select.php');
            } else {
                header('Location: index.php');
            }
            exit;
        } else {
            $error = $result['message'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Giriş - Switch Yönetim Sistemi</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            padding: 40px;
            width: 100%;
            max-width: 450px;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header i {
            font-size: 60px;
            color: #3b82f6;
            margin-bottom: 20px;
        }
        
        .login-header h1 {
            color: #e2e8f0;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: #94a3b8;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-group label {
            display: block;
            color: #e2e8f0;
            font-size: 14px;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        .input-wrapper {
            position: relative;
        }
        
        .input-wrapper i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #64748b;
            font-size: 16px;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 15px 12px 45px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid #334155;
            border-radius: 10px;
            color: #e2e8f0;
            font-size: 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            outline: none;
            border-color: #3b82f6;
            background: rgba(15, 23, 42, 0.8);
        }
        
        .form-control::placeholder {
            color: #64748b;
        }
        
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(59, 130, 246, 0.3);
        }
        
        .btn-login:active {
            transform: translateY(0);
        }
        
        .alert {
            padding: 12px 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
        }
        
        .login-footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #334155;
        }
        
        .login-footer p {
            color: #64748b;
            font-size: 13px;
        }
        

    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <img src="logo.png" alt="CHAMADA" style="width:60px;height:60px;object-fit:contain;margin-bottom:8px;">
            <h1>Switch Yönetim Sistemi</h1>
            <p>Giriş yapmak için bilgilerinizi girin</p>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <span><?php echo htmlspecialchars($error); ?></span>
            </div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <span><?php echo htmlspecialchars($success); ?></span>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <?php if ($returnUrl): ?>
            <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
            <?php endif; ?>
            <div class="form-group">
                <label for="username">Kullanıcı Adı</label>
                <div class="input-wrapper">
                    <i class="fas fa-user"></i>
                    <input type="text" id="username" name="username" class="form-control" 
                           placeholder="Kullanıcı adınızı girin" required autofocus>
                </div>
            </div>
            
            <div class="form-group">
                <label for="password">Şifre</label>
                <div class="input-wrapper">
                    <i class="fas fa-lock"></i>
                    <input type="password" id="password" name="password" class="form-control" 
                           placeholder="Şifrenizi girin" required>
                </div>
            </div>
            
            <button type="submit" class="btn-login">
                <i class="fas fa-sign-in-alt"></i>
                <span>Giriş Yap</span>
            </button>
        </form>
        
        <div class="login-footer">
            <p>&copy; 2026 Switch Yönetim Sistemi. Tüm hakları saklıdır.</p>
        </div>
    </div>
</body>
</html>
