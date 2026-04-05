from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    url = ""
    status = ""
    protocol = ""
    suspicious_patterns = ""
    length_score = ""
    domain_age = ""
    registration = ""
    blacklist_status = ""
    forms = ""
    scripts = ""
    headers = ""

    if request.method == "POST":
        url = request.form.get("url")

        # Placeholder values — replace with real scan logic
        status = "Safe"
        protocol = "HTTPS"
        suspicious_patterns = "None detected"
        length_score = "Normal"
        domain_age = "5 years"
        registration = "Google"
        blacklist_status = "Not blacklisted"
        forms = "2"
        scripts = "5 external scripts"
        headers = "Security headers present"

    return render_template(
        "index.html",
        url=url,
        status=status,
        protocol=protocol,
        suspicious_patterns=suspicious_patterns,
        length_score=length_score,
        domain_age=domain_age,
        registration=registration,
        blacklist_status=blacklist_status,
        forms=forms,
        scripts=scripts,
        headers=headers
    )

if __name__ == "__main__":
    app.run(debug=True)
