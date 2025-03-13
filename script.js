document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("ticketForm");

    form.addEventListener("submit", function (e) {
        e.preventDefault();

        // Validate Inputs
        let formData = new FormData(form);
        if (!formData.get("name") || !formData.get("email") || !formData.get("subject") || !formData.get("message")) {
            alert("Please fill all required fields.");
            return;
        }

        // Simulate Form Submission (Replace this with actual backend API call)
        setTimeout(() => {
            alert("✅ Your support ticket has been submitted successfully!");
            form.reset();
        }, 1000);
    });
});

function sendEmail(event) {
    event.preventDefault(); // Prevent form submission and page reload
  
    const form = document.getElementById("ticketForm");
  
    const params = {
      from_name: document.querySelector("#name").value,
      email_id: document.querySelector("#email").value,
      csid: document.querySelector("#csid").value,
      address: document.querySelector("#address").value,
      user_code: document.querySelector("#user_code").value,
      datetime: document.querySelector("#datetime").value,
      subject: document.querySelector("#subject").value,
      message: document.querySelector("#message").value,
      reply_to: document.querySelector("#email").value, // Optional
    };
  
    // Display loading message
    const messageBox = document.querySelector("#email-message");
    messageBox.textContent = "⏳ Sending Email...";
    messageBox.style.color = "blue";
  
    emailjs.send("service_sz1etk8", "template_j2oenkf", params)
      .then(() => {
        messageBox.textContent = "✅ Email Sent Successfully!";
        messageBox.style.color = "green";
        
        // Clear form after 2 seconds
        setTimeout(() => {
          messageBox.textContent = "";
          form.reset();
        }, 2000);
      })
      .catch(() => {
        messageBox.textContent = "❌ Failed to send message!";
        messageBox.style.color = "red";
  
        // Reset form even if failed
        setTimeout(() => {
          messageBox.textContent = "";
          form.reset();
        }, 2000);
      });
  }
  
  // Attach function to form submission
  document.getElementById("ticketForm").addEventListener("submit", sendEmail);
  