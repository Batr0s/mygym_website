<?php
require("../model/database.php");

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
    $tarifa = $requestData["tarifa"];
    
    if ($requestData["tarifa"] != "") {
        crear_usuario($con, $nombre, $apellidos, $edad, $password, $email, $telefono, $tarifa, 1);
        echo json_encode(["result" => "1"]);
    } else {
        echo json_encode(["result" => "0", "message" => "Escoge una tarifa"]);
    }
    
}
