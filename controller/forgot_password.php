<?php
require("../model/database.php");
require 'vendor/autoload.php';
use \Mailjet\Resources;


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $con = conectar();
    $jsonRequestBody  = file_get_contents('php://input');
    $requestData  = json_decode($jsonRequestBody , true);

    $action = $requestData["action"];
    if ($action == "send_email") {
        $email = $requestData ["email"];
        $errores = validar_email($email);

        // Si $errores contiene algún mensaje de error, la condición se cumple e intenta crear el usuario en la base de datos y enviar el 
        // email de bienvenida. Si encentra un error, lo captura con el catch y lo devuelve al cliente.
        if (empty($errores)) {
            try {
                // comprobar_email() lanza una Exception en caso de no encontrar el email.
                $nombre = comprobar_email($con, $email);
                // Creación de un token único para autenticar al usuario
                $token = uniqid();
                $hashedToken = hash('sha256', $token . $email);
                // caducidad_token() devuelve la fecha de caducidad (1h) del token en formato adecuado para mysql
                $caducidad_token = caducidad_token();
                // Crea el token y lo almacena en la base de datos
                crear_token($con, $hashedToken, $caducidad_token, $email);
                reset_pass_mail($nombre, $email, $hashedToken);

                echo json_encode(["result" => "1"]);
            } catch (Exception $error) {
                $message = $error->getMessage();
                echo json_encode(["result" => "0", "message" => $message]);
            }
        } else {
            echo json_encode(["result" => "0", "message" => $errores]);
        }
    } else if ($action == "change_password") {
        $password = $requestData ["password"];
        $confirmarPassword = $requestData ["confirmarPassword"];

        $errores = validar_password($password, $confirmarPassword);
        if (empty($errores)) {
            try {
                $token = $requestData ["token"];
                $email = comprobar_token($con, $token);
                cambiar_password($con, $email, $password);
                echo json_encode(["result" => "1"]);
            } catch (Exception $error) {
                $message = $error->getMessage();
                echo json_encode(["result" => "0", "message" => $message]);
            }
        } else {
            echo json_encode(["result" => "0", "message" => $errores]);
        }
    }
} else {
    echo json_encode(["error" => "La solicitud no es válida."]);
}


// Utiliza la API Mailjet para enviar un email de bienvenida al email del usuario recien registrado.
function reset_pass_mail($nombre, $email, $hashedToken) {
    $mj = new \Mailjet\Client('b48171b8cffa9cfefb02b7e305245fb1','60f70a3ed2e6d95eab7183be382169e5',true,['version' => 'v3.1']);
    $body = [
        'Messages' => [
        [
            'From' => [
            'Email' => "alvarokancor@gmail.com",
            'Name' => "VitalWay Gym"
            ],
            'To' => [
            [
                'Email' => $email,
                'Name' => $nombre
            ]
            ],
            'Subject' => "Restablecer tu contraseña en VitalWay Gym",
            'TextPart' => "Este correo electrónico te permite restablecer tu contraseña en VitalWay Gym.",
            'HTMLPart' => "<h3>Hola " . $nombre . ",</h3>
            <p>Se ha solicitado un cambio de contraseña para tu cuenta en <a href='http://localhost/m12/view/index.html'>VitalWay Gym</a>.</p>
            <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
            <a href='http://localhost/codigo_v8/view/change_password.html?token=$hashedToken'>Restablecer contraseña</a>
            <p>Este enlace caduca en 1 hora. Si no lo usas en ese tiempo, tendrás que solicitar otro.</p>
            <p>Atentamente,</p>
            Equipo VitalWay Gym",
            'CustomID' => "AppGettingStartedTest"
        ]
        ]
    ];
    $response = $mj->post(Resources::$Email, ['body' => $body]);
    // $response->success() && var_dump($response->getData());
}

// Valida el email
function validar_email($email) {
    $errores = array();
    // Validación formato correo electrónico.
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errores[] = 'El correo electrónico no tiene un formato válido.';
    }

    return $errores;
}

function validar_password($password, $confirmarPassword) {
    $errores = array();
    $expPassword = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/';
    $hasMinuscula = '/[a-z]/';
    $hasMayuscula = '/[A-Z]/';
    $hasDigito = '/[0-9]/';
    $hasSimbolo = '/[@$!%*#?&]/';
    $minLongitud = 8;

    // Validación contraseña. Debe tener 8 o más carácteres, minúscula, mayúscula, dígito y uno de los símbolos.
    if (!preg_match($expPassword, $password)) {
        if (!preg_match($hasMinuscula, $password)) {
            $errores[] = 'La contraseña no tiene letra minúscula.';
        } else if (!preg_match($hasMayuscula, $password)) {
            $errores[] = 'La contraseña no tiene letra mayúscula.';
        } else if (!preg_match($hasDigito, $password)) {
            $errores[] = 'La contraseña no tiene valor numérico.';
        } else if (!preg_match($hasSimbolo, $password)) {
            $errores[] = 'La contraseña no tiene un símbolo @$!%*#?&.';
        } else if (strlen($password) < $minLongitud) {
            $errores[] = 'La contraseña debe tener al menos 8 caracteres.';
        }
    }

    // Las dos contraseñas deben coincidir
    if ($password !== $confirmarPassword) {
        $errores[] = 'La contraseña y la confirmación de contraseña no coinciden.';
    }

    return $errores;
}

function caducidad_token() {
    $duracionToken = 3600; // 1 hour in seconds
    $fechaActual = time();
    $fechaCaducidad = date('Y-m-d H:i:s', $fechaActual + $duracionToken);
    return ($fechaCaducidad);
}

?>