// PhishGuard - lecture des QR codes contenus dans les images d'un message (« quishing »).
// Les images sont décodées sur le poste avec le décodeur QR de ZXing.Net (licence Apache 2.0,
// src/ThirdParty/ZXing) ; rien n'est envoyé à l'extérieur. L'adresse trouvée est ensuite analysée
// comme n'importe quel lien du message.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;

namespace PhishGuard
{
    public static class QrScan
    {
        const int MaxSide = 1600;      // au-delà, l'image est réduite (un QR code reste lisible)
        const int MinSide = 40;        // en dessous, ce n'est pas un QR code lisible (puces, logos)

        /// <summary>Texte des QR codes trouvés dans une image (PNG, JPEG, GIF, BMP), ou liste vide.</summary>
        public static List<string> Decode(byte[] image)
        {
            var found = new List<string>();
            if (image == null || image.Length < 100) return found;
            try
            {
                using (var ms = new MemoryStream(image))
                using (var src = Image.FromStream(ms, false, false))
                {
                    if (src.Width < MinSide || src.Height < MinSide) return found;
                    double scale = Math.Min(1.0, (double)MaxSide / Math.Max(src.Width, src.Height));
                    int w = Math.Max(1, (int)(src.Width * scale)), h = Math.Max(1, (int)(src.Height * scale));
                    using (var bmp = new Bitmap(w, h, PixelFormat.Format24bppRgb))
                    {
                        using (var g = Graphics.FromImage(bmp))
                        {
                            g.Clear(Color.White);   // fond blanc pour les images transparentes
                            g.DrawImage(src, 0, 0, w, h);
                        }
                        byte[] gray = Luminance(bmp);
                        string text = TryDecode(gray, w, h, false);
                        if (text == null) text = TryDecode(gray, w, h, true);   // QR code clair sur fond sombre
                        if (!string.IsNullOrEmpty(text)) found.Add(text);
                    }
                }
            }
            catch (Exception) { }   // image illisible ou format inconnu : rien à signaler
            return found;
        }

        static string TryDecode(byte[] gray, int w, int h, bool invert)
        {
            try
            {
                LuminanceSource source = new RGBLuminanceSource(gray, w, h, RGBLuminanceSource.BitmapFormat.Gray8);
                if (invert) source = source.invert();
                var hints = new Dictionary<DecodeHintType, object> { { DecodeHintType.TRY_HARDER, true } };
                foreach (Binarizer b in new Binarizer[] { new HybridBinarizer(source), new GlobalHistogramBinarizer(source) })
                {
                    var r = new QRCodeReader().decode(new BinaryBitmap(b), hints);
                    if (r != null && !string.IsNullOrEmpty(r.Text)) return r.Text;
                }
            }
            catch (Exception) { }
            return null;
        }

        static byte[] Luminance(Bitmap bmp)
        {
            int w = bmp.Width, h = bmp.Height;
            var gray = new byte[w * h];
            var data = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
            try
            {
                int stride = data.Stride;
                var row = new byte[stride];
                for (int y = 0; y < h; y++)
                {
                    System.Runtime.InteropServices.Marshal.Copy(IntPtr.Add(data.Scan0, y * stride), row, 0, stride);
                    for (int x = 0; x < w; x++)
                    {
                        int i = x * 3;   // BGR
                        gray[y * w + x] = (byte)((row[i] * 29 + row[i + 1] * 150 + row[i + 2] * 77) >> 8);
                    }
                }
            }
            finally { bmp.UnlockBits(data); }
            return gray;
        }
    }
}
