"""
Drishti - Demo Data Generator
Generates realistic Indian cybercrime digital forensics evidence for Rahul Sharma UPI fraud case.
"""

import os
import random
from datetime import datetime, timedelta
import pandas as pd
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
import pypdf

DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_data")


def ensure_demo_data_dir():
    os.makedirs(DEMO_DIR, exist_ok=True)
    return DEMO_DIR


def generate_transactions_csv(target_path=None):
    if not target_path:
        target_path = os.path.join(DEMO_DIR, "transactions.csv")

    random.seed(42)
    rows = []
    base_time = datetime(2026, 10, 10, 8, 30, 0)
    
    # Usual Rahul merchants and friends
    frequent_receivers = [
        ("Zomato Online", "zomato@icici", "ICIC0000011", "982001122334"),
        ("Swiggy Delivery", "swiggy@hdfcbank", "HDFC0000045", "983002233445"),
        ("Mother Dairy Kanpur", "dairy.kanpur@paytm", "PYTM0123456", "984003344556"),
        ("Kanpur Electricity Discom", "kesco.bill@sbi", "SBIN0000120", "985004455667"),
        ("Aman Verma (Friend)", "aman.verma@oksbi", "SBIN0003412", "302918273645"),
        ("Pooja Sharma (Sister)", "pooja.sharma@okaxis", "UTIB0000789", "918273645012"),
        ("Airtel Postpaid", "airtel.bill@airtel", "AIRP0000001", "112233445566"),
        ("Apollo Pharmacy", "apollo.meds@icici", "ICIC0000012", "778899001122"),
        ("Reliance Fresh", "reliance.retail@hdfcbank", "HDFC0000099", "665544332211"),
        ("Local Kirana Store", "gupta.store@upi", "PUNB0001234", "554433221100"),
    ]

    current_time = base_time
    victim_ac = "30192837465"
    victim_upi = "rahul.sharma@oksbi"
    
    # 58 normal transactions over 7 days
    for i in range(58):
        # advance by 2 to 6 hours during daytime (8 AM to 10 PM)
        hour_increment = random.randint(2, 5)
        current_time += timedelta(hours=hour_increment, minutes=random.randint(5, 50))
        if current_time.hour < 8:
            current_time = current_time.replace(hour=random.randint(8, 11))
        elif current_time.hour >= 23:
            current_time = current_time.replace(hour=random.randint(8, 10)) + timedelta(days=1)

        rec_name, rec_upi, rec_ifsc, rec_ac = random.choice(frequent_receivers)
        amount = round(random.uniform(45.0, 3200.0), 2)
        tx_type = "DEBIT"
        status = "SUCCESS"
        ref_no = f"UPI{random.randint(100000000000, 999999999999)}"

        rows.append({
            "Transaction_ID": f"TXN{10000 + i}",
            "Timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Sender_Account": victim_ac,
            "Sender_UPI": victim_upi,
            "Receiver_Name": rec_name,
            "Receiver_Account": rec_ac,
            "Receiver_IFSC": rec_ifsc,
            "Receiver_UPI": rec_upi,
            "Amount_INR": amount,
            "Type": tx_type,
            "Status": status,
            "Reference_No": ref_no,
            "Location_IP": "122.161.45.10",
            "Device": "Samsung Galaxy S21"
        })

    # Fraud transactions: 18 Oct 2026, 02:14 AM session
    # Fraud Tx 1
    rows.append({
        "Transaction_ID": "TXN10058",
        "Timestamp": "2026-10-18 02:17:45",
        "Sender_Account": victim_ac,
        "Sender_UPI": victim_upi,
        "Receiver_Name": "Ramesh Traders",
        "Receiver_Account": "981234564521",
        "Receiver_IFSC": "HDFC0001244",
        "Receiver_UPI": "ramesh.traders@okhdfcbank",
        "Amount_INR": 49000.00,
        "Type": "DEBIT",
        "Status": "SUCCESS",
        "Reference_No": "UPI429182910392",
        "Location_IP": "103.87.212.45",
        "Device": "Linux/Chrome (Unauthorized Session)"
    })

    # Fraud Tx 2
    rows.append({
        "Transaction_ID": "TXN10059",
        "Timestamp": "2026-10-18 02:21:10",
        "Sender_Account": victim_ac,
        "Sender_UPI": victim_upi,
        "Receiver_Name": "Ramesh Traders",
        "Receiver_Account": "981234564521",
        "Receiver_IFSC": "HDFC0001244",
        "Receiver_UPI": "ramesh.traders@okhdfcbank",
        "Amount_INR": 31000.00,
        "Type": "DEBIT",
        "Status": "SUCCESS",
        "Reference_No": "UPI429182910405",
        "Location_IP": "103.87.212.45",
        "Device": "Linux/Chrome (Unauthorized Session)"
    })

    # Mule forwarding 1
    rows.append({
        "Transaction_ID": "TXN10060",
        "Timestamp": "2026-10-18 02:25:30",
        "Sender_Account": "981234564521",
        "Sender_UPI": "ramesh.traders@okhdfcbank",
        "Receiver_Name": "Vikram Enterprises (Mule 1)",
        "Receiver_Account": "440918237712",
        "Receiver_IFSC": "ICIC0000389",
        "Receiver_UPI": "vikram.ent@okicici",
        "Amount_INR": 45000.00,
        "Type": "TRANSFER",
        "Status": "SUCCESS",
        "Reference_No": "IMPS66281928011",
        "Location_IP": "103.87.212.45",
        "Device": "Web Portal"
    })

    # Mule forwarding 2
    rows.append({
        "Transaction_ID": "TXN10061",
        "Timestamp": "2026-10-18 02:27:00",
        "Sender_Account": "981234564521",
        "Sender_UPI": "ramesh.traders@okhdfcbank",
        "Receiver_Name": "Deepak Rawat (Mule 2)",
        "Receiver_Account": "552109483319",
        "Receiver_IFSC": "SBIN0004120",
        "Receiver_UPI": "deepak99@oksbi",
        "Amount_INR": 34000.00,
        "Type": "TRANSFER",
        "Status": "SUCCESS",
        "Reference_No": "IMPS66281928045",
        "Location_IP": "103.87.212.45",
        "Device": "Web Portal"
    })

    df = pd.DataFrame(rows)
    df.to_csv(target_path, index=False)
    return target_path


def generate_login_logs_csv(target_path=None):
    if not target_path:
        target_path = os.path.join(DEMO_DIR, "login_logs.csv")

    random.seed(42)
    rows = []
    base_time = datetime(2026, 10, 11, 9, 15, 0)
    
    # 25 normal logins from Rahul's typical device and Kanpur IP
    for i in range(25):
        base_time += timedelta(hours=random.randint(4, 9), minutes=random.randint(10, 45))
        if base_time.hour < 7:
            base_time = base_time.replace(hour=random.randint(8, 10))
        elif base_time.hour >= 23:
            base_time = base_time.replace(hour=random.randint(8, 9)) + timedelta(days=1)

        rows.append({
            "Log_ID": f"LOG{2000 + i}",
            "User_ID": "rahul.sharma",
            "Timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
            "IP_Address": random.choice(["122.161.45.10", "122.161.45.12", "122.161.45.15"]),
            "City": "Kanpur",
            "State": "Uttar Pradesh",
            "ISP": "Bharti Airtel Broadband",
            "Device_Type": "Mobile App (Android 14)",
            "Device_Model": "Samsung Galaxy S21",
            "Login_Status": "SUCCESS",
            "Auth_Method": "Biometric / MPIN"
        })

    # Suspicious unauthorized login at 2:14 AM from Delhi IP
    rows.append({
        "Log_ID": "LOG2025",
        "User_ID": "rahul.sharma",
        "Timestamp": "2026-10-18 02:14:22",
        "IP_Address": "103.87.212.45",
        "City": "Delhi",
        "State": "Delhi NCR",
        "ISP": "Excitel Broadband",
        "Device_Type": "Browser (WebNetBanking)",
        "Device_Model": "Linux x86_64 / Chrome 129",
        "Login_Status": "SUCCESS",
        "Auth_Method": "NetBanking Password + Intercepted OTP"
    })

    df = pd.DataFrame(rows)
    df.to_csv(target_path, index=False)
    return target_path


def generate_call_logs_csv(target_path=None):
    if not target_path:
        target_path = os.path.join(DEMO_DIR, "call_logs.csv")

    rows = [
        {"Call_ID": "CAL901", "Timestamp": "2026-10-16 11:20:00", "Caller_Number": "+91-94501-11223", "Caller_Name": "Pooja Sharma", "Call_Type": "INCOMING", "Duration_Sec": 184, "Status": "ANSWERED"},
        {"Call_ID": "CAL902", "Timestamp": "2026-10-16 14:45:10", "Caller_Number": "+91-98390-55443", "Caller_Name": "Office Colleague", "Call_Type": "OUTGOING", "Duration_Sec": 95, "Status": "ANSWERED"},
        {"Call_ID": "CAL903", "Timestamp": "2026-10-16 19:10:30", "Caller_Number": "+91-91250-99881", "Caller_Name": "Aman Verma", "Call_Type": "INCOMING", "Duration_Sec": 240, "Status": "ANSWERED"},
        {"Call_ID": "CAL904", "Timestamp": "2026-10-17 10:15:00", "Caller_Number": "+91-94501-11223", "Caller_Name": "Pooja Sharma", "Call_Type": "OUTGOING", "Duration_Sec": 62, "Status": "ANSWERED"},
        # Scam call!
        {"Call_ID": "CAL905", "Timestamp": "2026-10-17 19:42:00", "Caller_Number": "+91-98765-43210", "Caller_Name": "Bank KYC Verification / Unknown", "Call_Type": "INCOMING", "Duration_Sec": 312, "Status": "ANSWERED"},
        {"Call_ID": "CAL906", "Timestamp": "2026-10-17 21:05:40", "Caller_Number": "+91-91250-99881", "Caller_Name": "Aman Verma", "Call_Type": "OUTGOING", "Duration_Sec": 45, "Status": "ANSWERED"}
    ]
    df = pd.DataFrame(rows)
    df.to_csv(target_path, index=False)
    return target_path


def generate_whatsapp_chat(target_path=None):
    if not target_path:
        target_path = os.path.join(DEMO_DIR, "whatsapp_chat.txt")

    content = """[17/10/26, 19:45:12] Aman Verma: Hey Rahul, are we meeting tomorrow at Civil Lines?
[17/10/26, 19:46:05] Rahul Sharma: Yes Aman, around 5 PM after office.
[17/10/26, 19:48:30] +91-98765-43210: Dear SBI Customer Rahul Sharma, your YONO NetBanking & UPI account KYC has expired. As per RBI directive #KYC-2026-SBI, your account will be suspended within 24 hours. Update KYC online now: https://sbi-kyc-update-portal.in/verify
[17/10/26, 19:49:15] Rahul Sharma: Is this official? Can I visit the Mall Road branch tomorrow morning?
[17/10/26, 19:49:50] +91-98765-43210: Sir, automated security hold triggers at midnight. Your debit card and UPI linked to mobile +91-98765-43210 will be deactivated. Please complete instant biometric/Aadhaar verification at https://sbi-kyc-update-portal.in/verify to avoid penalty of Rs 2500.
[17/10/26, 19:54:10] Rahul Sharma: Okay sir, opening link now. It asked for NetBanking username and OTP.
[17/10/26, 19:55:02] +91-98765-43210: Enter the 6-digit verification code received on SMS to approve server token sync. Do not share code with anyone other than this portal.
[17/10/26, 19:56:45] Rahul Sharma: Done, filled the form and submitted the code on portal.
[17/10/26, 19:57:12] +91-98765-43210: KYC verification is under automated audit. Do not log into YONO app until morning 8 AM for sync to complete.
[18/10/26, 06:45:10] Rahul Sharma: Hello?? I got SMS alerts that Rs 49000 and Rs 31000 debited at 2 AM to Ramesh Traders! Pick up my call!
[18/10/26, 06:45:30] +91-98765-43210: This number is no longer accepting messages. (User blocked or account deleted)
"""
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)
    return target_path


def generate_screenshots():
    ensure_demo_data_dir()
    orig_path = os.path.join(DEMO_DIR, "screenshot_original.png")
    edit_path = os.path.join(DEMO_DIR, "screenshot_edited.png")

    # Generate Original Screenshot (clean UPI receipt)
    width, height = 720, 1280
    img = Image.new("RGB", (width, height), color=(18, 22, 34))
    draw = ImageDraw.Draw(img)

    # Header bar
    draw.rectangle([0, 0, width, 120], fill=(24, 30, 48))
    # Green tick circle
    draw.ellipse([width // 2 - 50, 160, width // 2 + 50, 260], fill=(16, 185, 129))
    draw.line([width // 2 - 25, 210, width // 2 - 5, 230], fill=(255, 255, 255), width=8)
    draw.line([width // 2 - 5, 230, width // 2 + 25, 190], fill=(255, 255, 255), width=8)

    # Details card
    draw.rectangle([40, 300, width - 40, 1180], fill=(26, 32, 53), outline=(45, 55, 80), width=2)
    
    # Text elements
    draw.text((width // 2 - 140, 330), "Payment Successful", fill=(255, 255, 255))
    draw.text((width // 2 - 110, 380), "INR 49,000.00", fill=(16, 185, 129))
    draw.text((70, 460), "Paid to: Ramesh Traders", fill=(220, 225, 235))
    draw.text((70, 510), "UPI ID: ramesh.traders@okhdfcbank", fill=(148, 163, 184))
    draw.text((70, 560), "Bank A/C: 981234564521 (HDFC Bank)", fill=(148, 163, 184))
    draw.text((70, 610), "UPI Ref No: 429182910392", fill=(148, 163, 184))
    draw.text((70, 660), "Debited from: Rahul Sharma (SBI XXXX7465)", fill=(148, 163, 184))
    draw.text((70, 710), "Timestamp: 18 Oct 2026, 02:17:45 AM IST", fill=(148, 163, 184))
    draw.text((70, 760), "IP Location: 103.87.212.45 (Delhi)", fill=(244, 63, 94))

    # Add realistic metadata to original
    png_meta = PngImagePlugin.PngInfo()
    png_meta.add_text("Software", "Android System Screenshot / SBI YONO Mobile v4.8")
    png_meta.add_text("Creation Time", "2026-10-18T02:17:55")
    png_meta.add_text("Device", "Samsung SM-G991B")
    img.save(orig_path, "PNG", pnginfo=png_meta)

    # Generate Edited Screenshot (tampered amount, modified metadata)
    img_edit = img.copy()
    draw_edit = ImageDraw.Draw(img_edit)
    # Tamper the amount box to simulate Photoshop alteration (INR 49,000 -> INR 4,900)
    # Paint over the amount with slightly mismatched color & noise
    draw_edit.rectangle([width // 2 - 130, 370, width // 2 + 130, 430], fill=(28, 35, 58))
    # Re-draw altered text with slight artifact
    draw_edit.text((width // 2 - 95, 380), "INR 4,900.00", fill=(34, 197, 94))
    # Also alter receiver line
    draw_edit.rectangle([65, 455, 450, 495], fill=(28, 35, 58))
    draw_edit.text((70, 460), "Paid to: Ramesh Traders (Refunded)", fill=(220, 225, 235))

    # Add Photoshop metadata to edited image
    png_meta_edit = PngImagePlugin.PngInfo()
    png_meta_edit.add_text("Software", "Adobe Photoshop 2024 (Windows)")
    png_meta_edit.add_text("Creation Time", "2026-10-18T10:35:12")
    png_meta_edit.add_text("History", "Layer modification, Text Tool edit")
    img_edit.save(edit_path, "PNG", pnginfo=png_meta_edit)

    return orig_path, edit_path


def generate_fake_kyc_pdf(target_path=None):
    if not target_path:
        target_path = os.path.join(DEMO_DIR, "fake_kyc_notice.pdf")

    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({
        "/Title": "URGENT NOTICE: STATE BANK OF INDIA - KYC COMPLIANCE",
        "/Author": "SBI Cyber Helpdesk",
        "/Subject": "Account Suspension Warning Notice",
        "/Creator": "Canva PDF Export Tool v4.1",
        "/Producer": "iLovePDF Editor / Tampered",
        "/CreationDate": "D:20261017183000",
        "/ModDate": "D:20261018091500"
    })
    with open(target_path, "wb") as f:
        writer.write(f)
    return target_path


def generate_all_demo_files():
    ensure_demo_data_dir()
    tx_path = generate_transactions_csv()
    login_path = generate_login_logs_csv()
    call_path = generate_call_logs_csv()
    chat_path = generate_whatsapp_chat()
    orig_img, edit_img = generate_screenshots()
    pdf_path = generate_fake_kyc_pdf()
    return {
        "transactions.csv": tx_path,
        "login_logs.csv": login_path,
        "call_logs.csv": call_path,
        "whatsapp_chat.txt": chat_path,
        "screenshot_original.png": orig_img,
        "screenshot_edited.png": edit_img,
        "fake_kyc_notice.pdf": pdf_path,
    }


if __name__ == "__main__":
    files = generate_all_demo_files()
    print("Demo files generated successfully:")
    for name, path in files.items():
        print(f" - {name}: {os.path.getsize(path)} bytes")
