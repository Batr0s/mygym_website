<?php
require("../model/database.php");
require 'vendor/autoload.php';
use \Mailjet\Resources;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $con = conectar();
    $jsonRequestBody  = file_get_contents('php://input');
    $requestData  = json_decode($jsonRequestBody , true);

    $nombre = $requestData ["nombre"];
    $apellidos = $requestData ["apellidos"];
    $edad = $requestData ["edad"];
    $email = $requestData ["email"];
    $telefono = $requestData ["telefono"];
    $password = $requestData ["password"];
    $confirmarPassword = $requestData ["confirmarPassword"];
    // response es la respuesta del captcha, en caso de NO ser verificado la variable estará vacía. 
    $response = $requestData ["response"];

    $errores = validar_registro($nombre, $apellidos, $edad, $email, $telefono, $password, $confirmarPassword, $response);

    // Si $errores contiene algún mensaje de error, la condición se cumple e intenta crear el usuario en la base de datos y enviar el 
    // email de bienvenida. Si encentra un error, lo captura con el catch y lo devuelve al cliente.
    if (empty($errores)) {
        try {
            $resultado = valida_usuario($con, $email, $password);
            if ($resultado->num_rows > 0) {
                throw new Exception("Correo electrónico existente. Escoge uno nuevo.");
            }
            welcome_mail($nombre, $email);
            echo json_encode(["result" => "1"]);
        } catch (Exception $error) {
            $message = $error->getMessage();

            if (strpos($message, "Duplicate entry") !== false) {
                echo json_encode(["result" => "0", "message" => "Correo electrónico existente. Escoge uno nuevo."]);
            } else {
                echo json_encode(["result" => "0", "message" => $message]);
            }
        }
    } else {
        echo json_encode(["result" => "0", "message" => $errores]);
    }
} else {
    echo json_encode(["error" => "La solicitud no es válida."]);
}

// Utiliza la API Mailjet para enviar un email de bienvenida al email del usuario recien registrado.
function welcome_mail($nombre, $email) {
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
            'Subject' => " ¡Bienvenido a VitalWay Gym!",
            'TextPart' => "Email de bienvenida",
            'HTMLPart' => "<h3>¡Hola ".$nombre."!</h3>
            <p>¡Bienvenido a <a href='http://localhost/m12/view/login.html'>VitalWay Gym</a>! Estamos encantados de tenerte como parte de nuestra comunidad fitness. Queremos que te sientas inspirado y motivado cada vez que nos visites. 
            No dudes en acercarte si necesitas consejos, motivación o simplemente deseas compartir tus logros con nosotros.</p>
            <p>¡Nos vemos pronto en el gimnasio!</p>

            <p>Atentamente,</p>
            Equipo VitalWay Gym",
            'CustomID' => "AppGettingStartedTest"
        ]
        ]
    ];
    $response = $mj->post(Resources::$Email, ['body' => $body]);
    // $response->success() && var_dump($response->getData());
}

// return $errores. En caso de no pasar la validación se añade el mensaje de error en el array.
function validar_registro($nombre, $apellidos, $edad, $email, $telefono, $password, $confirmarPassword, $response) {
    $errores = array();

    // Key secreta del recaptcha
    $secretkey = "6LexDMkpAAAAANgC2reGcKGBG-dFdZIFcmxunDhC";
    $respuesta = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$secretkey&response=$response");
    $atributos = json_decode($respuesta, true);

    if ($atributos["success"] == false) {
        $errores[] = "Verificar captcha";
    }

    if (strlen($nombre) < 2 || strlen($apellidos) < 2) {
        $errores[] = 'Nombre y apellidos deben tener al menos dos caracteres.';
    }

    // Validación mayor de edad.
    $fechaNacimiento = new DateTime($edad);
    $hoy = new DateTime();
    $edadCalculada = $hoy->diff($fechaNacimiento)->y;
    if ($edadCalculada < 18) {
        $errores[] = 'Debes ser mayor de edad para registrarte.';
    }

    // Validación formato correo electrónico.
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errores[] = 'El correo electrónico no tiene un formato válido.';
    }

    // Validación teléfono tiene 9 números.
    if (!empty($telefono) && !preg_match('/^\d{9}$/', $telefono)) {
        $errores[] = 'El número de teléfono debe tener 9 números.';
    }

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




?>