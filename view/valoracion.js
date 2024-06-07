const formulario = document.querySelector('#formulario-valoracion');
const mensaje = document.querySelector('#mensaje');

formulario.addEventListener('submit', async (event) => {
    event.preventDefault();

    const claseSeleccionada = document.querySelector('#clase').value;
    const valoracionSeleccionada = document.querySelector('input[name="value-radio"]:checked');

    if (!valoracionSeleccionada) {
        mensaje.textContent = 'Por favor, selecciona una valoración.';
        return;
    }

    const valoracion = parseInt(valoracionSeleccionada.value);
    
    try {
        // Realiza una solicitud fetch al servidor (ajusta la URL según tu configuración)
        const respuesta = await fetch('../controller/valoracion.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ clase: claseSeleccionada, valoracion }),
        });

        if (respuesta.ok) {
            mensaje.textContent = 'Operación exitosa: valoración guardada.';
        } else {
            mensaje.textContent = 'Error al guardar la valoración en el servidor.';
        }
    } catch (error) {
        console.error('Error de red:', error);
        mensaje.textContent = 'Error de red al enviar la valoración.';
    }
});
