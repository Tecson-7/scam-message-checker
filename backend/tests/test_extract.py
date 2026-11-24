from app.services.extract import extract


def test_bare_and_full_urls():
    r = extract("Update KYC at sbi-kyc.xyz/login or https://bit.ly/3abc. Thanks")
    assert "sbi-kyc.xyz/login" in r["urls"]
    assert "https://bit.ly/3abc" in r["urls"]


def test_email_is_not_a_url_or_upi():
    r = extract("Mail us at help@gmail.com")
    assert r["urls"] == []
    assert r["upi_ids"] == []
    assert r["emails"] == ["help@gmail.com"]


def test_indian_phones():
    r = extract("Call +91 98765 43210 or 9123456789 now")
    assert r["phones"] == ["9876543210", "9123456789"]


def test_otp_is_not_a_phone():
    assert extract("Your OTP is 482913")["phones"] == []


def test_upi_ids():
    r = extract("Pay Rs.10 to refund.desk@ybl to claim")
    assert r["upi_ids"] == ["refund.desk@ybl"]


def test_amounts():
    r = extract("Pay ₹1,499.50 or Rs. 20 or INR 300")
    assert r["amounts"] == [1499.5, 20.0, 300.0]
