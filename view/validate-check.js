document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    const togglePassword = document.getElementById('togglePassword');
    const requirementListItems = document.querySelectorAll('#requirement-list li');
    const checkmarks = document.querySelectorAll('.check');
    const submitButton = document.getElementById('submitButton');

    let showPassword = false;

    const requirements = [
        { regex: /.{8,}/, class: 'length', index: 0 },
        { regex: /[0-9]/, class: 'number', index: 1 },
        { regex: /[a-z]/, class: 'lowercase', index: 2 },
        { regex: /[A-Z]/, class: 'uppercase', index: 3 },
        { regex: /[^A-Za-z0-9]/, class: 'special', index: 4 }
    ];

    const checkRequirements = () => {
        let allMet = true;
        requirements.forEach((req) => {
            const item = document.querySelector(`.${req.class}`);
            const checkmark = checkmarks[req.index];
            const regex = req.regex;
            const isValid = regex.test(passwordInput.value);
            if (isValid) {
                item.classList.add('valid');
                checkmark.style.color = 'green';
            } else {
                item.classList.remove('valid');
                checkmark.style.color = '';
                allMet = false;
            }
        });
        return allMet;
    };

    passwordInput.addEventListener('input', () => {
        const allRequirementsMet = checkRequirements();
        submitButton.disabled = !allRequirementsMet;
    });

    togglePassword.addEventListener('click', () => {
        showPassword = !showPassword;
        passwordInput.type = showPassword ? 'text' : 'password';
        togglePassword.classList.toggle('fa-eye-slash');
    });
});