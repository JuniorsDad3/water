// static/js/app.js
document.addEventListener("DOMContentLoaded", function() {
    const form = document.getElementById("case-form");
    form.addEventListener("submit", function(event) {
        event.preventDefault();
        alert("Form submitted successfully!");
        // Implement form submission logic here
    });
});
