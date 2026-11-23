using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace PacketTrace
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length == 3 && args[0] == "--record-demo")
            {
                try
                {
                    File.WriteAllText(args[2], Demo.Record(args[1]), Encoding.UTF8);
                    return 0;
                }
                catch (Exception ex)
                {
                    File.WriteAllText(args[2], ex.GetBaseException().Message, Encoding.UTF8);
                    return 1;
                }
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainWindow(args.Length == 1 ? args[0] : null));
            return 0;
        }
    }
}
