/**
 * Después de validar el formulario, tanto en cliente como en servidor, 
 */
function create_user () {
    // Inputs del formulario
    let nombre = document.getElementById('nombre').value;
    let apellidos = document.getElementById('apellidos').value;
    let edad = document.getElementById('edad').value;
    let email = document.getElementById('email').value;
    let telefono = document.getElementById('telefono').value;
    let password = document.getElementById('password').value;

    const radio_input = document.getElementsByName('tarifa');
    let tarifa = '';
  
    for (const radio of radio_input) {
      if (radio.checked) {
        tarifa = radio.value;
        break;
      }
    }

    const datos = {
        nombre,
        apellidos,
        edad,
        email,
        telefono,
        password,
        tarifa
    };

    fetch('../controller/create-user.php', {
        method: 'POST',
        headers: {
            'Content-Type':'application/json'
        },
        body: JSON.stringify(datos)
    })
    .then(response => response.json())
    .then(data => {
    if (data.result === "1") {
        alert("¡Registro exitoso!");
        window.location.href = "login.html";
    } else if (data.result === "0") {
        alert("Error en el registro: " + data.message);
    }
    })
    .catch(error => {
        console.error('Error en la solicitud: ' + error);
        alert("Error en la solicitud. Inténtalo nuevamente.");
    });
} 

