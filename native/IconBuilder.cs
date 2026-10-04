using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Collections.Generic;

// Keep the Windows icon consistent with ui/assets/icon.svg.
class IconBuilder {
 static int Main(string[] args) {
  int[] sizes = {16,20,24,32,40,48,64,96,128,256}; var images = new List<byte[]>();
  foreach (int size in sizes) {
   using (var bitmap = new Bitmap(size,size,PixelFormat.Format32bppArgb)) {
    using (var graphics = Graphics.FromImage(bitmap)) {
     graphics.Clear(Color.Transparent); float unit = size / 24f;
     graphics.SmoothingMode = SmoothingMode.AntiAlias;
     using (var shape = new GraphicsPath())
     using (var background = new SolidBrush(Color.FromArgb(255,38,40,41))) {
      float corner = 4 * unit;
      shape.AddArc(0,0,corner,corner,180,90);
      shape.AddArc(size-corner,0,corner,corner,270,90);
      shape.AddArc(size-corner,size-corner,corner,corner,0,90);
      shape.AddArc(0,size-corner,corner,corner,90,90);
      shape.CloseFigure(); graphics.FillPath(background,shape);
     }
     using (var ink = new Pen(Color.FromArgb(255,184,189,177),1.75f*unit)) {
      ink.LineJoin = LineJoin.Miter;
      graphics.DrawPolygon(ink,new[] {new PointF(12*unit,1.5f*unit),new PointF(21.5f*unit,7.5f*unit),new PointF(21.5f*unit,16.5f*unit),new PointF(12*unit,22.5f*unit),new PointF(2.5f*unit,16.5f*unit),new PointF(2.5f*unit,7.5f*unit)});
      graphics.DrawLines(ink,new[] {new PointF(7.5f*unit,7.5f*unit),new PointF(12*unit,13*unit),new PointF(16.5f*unit,7.5f*unit)});
      graphics.DrawLine(ink,12*unit,13*unit,12*unit,18*unit);
     }
    }
    using (var stream = new MemoryStream()) { bitmap.Save(stream,ImageFormat.Png); images.Add(stream.ToArray()); }
   }
  }
  using (var writer = new BinaryWriter(File.Create(args[0]))) {
   writer.Write((ushort)0); writer.Write((ushort)1); writer.Write((ushort)sizes.Length);
   int offset = 6 + sizes.Length * 16;
   for (int i=0;i<sizes.Length;i++) {
    writer.Write((byte)(sizes[i]==256?0:sizes[i])); writer.Write((byte)(sizes[i]==256?0:sizes[i])); writer.Write((byte)0);writer.Write((byte)0);
    writer.Write((ushort)1); writer.Write((ushort)32); writer.Write(images[i].Length);writer.Write(offset);offset += images[i].Length;
   }
   foreach (var image in images) writer.Write(image);
  }return 0;
 }
}
