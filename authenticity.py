"""
Drishti - Digital Authenticity Verification Module
Implements Error Level Analysis (ELA), EXIF/PNG metadata forensics, and PDF metadata inspection.
Detects tampering, edited screenshots, and modified documents.
"""

import io
import os
from PIL import Image, ImageChops, ImageEnhance, ExifTags
import numpy as np
import pypdf
from datetime import datetime


def perform_ela(image_bytes: bytes, quality: int = 90, scale: int = 15):
    """
    Performs Error Level Analysis (ELA) on an image.
    Re-saves image at given JPEG quality and computes the amplified difference.
    Altered/tampered regions exhibit significantly higher error rates.
    """
    original = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    
    # Save to in-memory JPEG
    temp_buf = io.BytesIO()
    original.save(temp_buf, "JPEG", quality=quality)
    temp_buf.seek(0)
    
    resaved = Image.open(temp_buf).convert("RGB")
    
    # Compute absolute difference
    diff = ImageChops.difference(original, resaved)
    
    # Calculate scale factor or use amplifier
    extrema = diff.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0:
        max_diff = 1
    
    # Enhance difference
    scale_factor = min(255.0 / max_diff, scale)
    enhanced = ImageEnhance.Brightness(diff).enhance(scale_factor)
    
    # Compute quantitative ELA tampering metric
    diff_arr = np.array(diff)
    mean_diff = float(np.mean(diff_arr))
    max_diff_val = float(np.max(diff_arr))
    variance_diff = float(np.var(diff_arr))

    return original, enhanced, {
        "mean_diff": round(mean_diff, 2),
        "max_diff": round(max_diff_val, 2),
        "variance": round(variance_diff, 2),
        "scale_applied": round(scale_factor, 1)
    }


def extract_image_metadata(image_bytes: bytes):
    """
    Extracts EXIF and PNG textual metadata, searching for evidence of editing tools.
    """
    img = Image.open(io.BytesIO(image_bytes))
    meta_dict = {}
    warnings = []
    suspicious_software = [
        "photoshop", "gimp", "canva", "picsart", "snapseed", 
        "lightroom", "pixlr", "paint.net", "photopea"
    ]
    
    # PNG metadata
    if hasattr(img, "text") and img.text:
        for k, v in img.text.items():
            meta_dict[str(k)] = str(v)
            val_lower = str(v).lower()
            for s in suspicious_software:
                if s in val_lower:
                    warnings.append(f"Altered with image editing software: '{v}' in PNG tag '{k}'")

    # EXIF metadata (JPEG)
    try:
        exif_raw = img._getexif()
        if exif_raw:
            for tag_id, value in exif_raw.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                meta_dict[str(tag_name)] = str(value)
                val_lower = str(value).lower()
                for s in suspicious_software:
                    if s in val_lower:
                        warnings.append(f"Image edited with '{value}' (EXIF Tag: {tag_name})")
        else:
            if img.format in ["JPEG", "JPG"]:
                warnings.append("EXIF metadata stripped (Common indicator of forwarding via web/social messaging)")
    except Exception:
        pass

    # Check for basic dimensions & format
    meta_dict["Format"] = img.format
    meta_dict["Dimensions"] = f"{img.width} x {img.height} px"
    meta_dict["Color Mode"] = img.mode

    # Authenticity Score calculation
    authenticity_score = 98
    if warnings:
        authenticity_score -= len(warnings) * 35
    
    authenticity_score = max(10, min(100, authenticity_score))

    return meta_dict, warnings, authenticity_score


def analyze_pdf_metadata(pdf_bytes: bytes):
    """
    Inspects PDF document metadata for post-creation tampering or suspicious generators.
    """
    meta_dict = {}
    warnings = []
    
    try:
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        doc_info = reader.metadata or {}

        for k, v in doc_info.items():
            clean_key = str(k).replace("/", "")
            meta_dict[clean_key] = str(v)

        meta_dict["Page Count"] = str(len(reader.pages))

        # Check Creator & Producer
        creator = meta_dict.get("Creator", "").lower()
        producer = meta_dict.get("Producer", "").lower()
        
        suspicious_pdf_tools = ["canva", "ilovepdf", "sejda", "photoshop", "tampered", "pdf-modifier", "pdfedit"]
        for tool in suspicious_pdf_tools:
            if tool in creator or tool in producer:
                warnings.append(f"PDF generated/modified by suspicious third-party tool: '{meta_dict.get('Producer', creator)}'")

        # Compare CreationDate and ModDate
        creation_date = meta_dict.get("CreationDate", "")
        mod_date = meta_dict.get("ModDate", "")
        if creation_date and mod_date and creation_date != mod_date:
            warnings.append(f"Document modified after initial issuance: Created {creation_date} | Modified {mod_date}")

    except Exception as e:
        warnings.append(f"Error parsing PDF structure: {str(e)}")

    authenticity_score = 95
    if warnings:
        authenticity_score -= len(warnings) * 30
    authenticity_score = max(15, min(100, authenticity_score))

    return meta_dict, warnings, authenticity_score
