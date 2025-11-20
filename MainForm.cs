using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using System.Threading.Tasks;

namespace SeshatEVTXAnalyzer
{
    public class MainForm : Form
    {
        private Button btnSelectFiles = null!;
        private TextBox txtOutput = null!;
        private OpenFileDialog openFileDialog = null!;
        private FolderBrowserDialog folderBrowserDialog = null!;

        private CheckBox chkUseTimeFilter = null!;
        private DateTimePicker dtpStart = null!;
        private DateTimePicker dtpEnd = null!;

        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            ComponentResourceManager resources = new ComponentResourceManager(typeof(MainForm));
            btnSelectFiles = new Button();
            txtOutput = new TextBox();
            openFileDialog = new OpenFileDialog();
            folderBrowserDialog = new FolderBrowserDialog();
            chkUseTimeFilter = new CheckBox();
            dtpStart = new DateTimePicker();
            dtpEnd = new DateTimePicker();
            SuspendLayout();
            
            // btnSelectFiles
            
            btnSelectFiles.Location = new Point(3, 14);
            btnSelectFiles.Name = "btnSelectFiles";
            btnSelectFiles.Size = new Size(150, 30);
            btnSelectFiles.TabIndex = 0;
            btnSelectFiles.Text = "Select EVTX Files";
            btnSelectFiles.UseVisualStyleBackColor = true;
            btnSelectFiles.Click += BtnSelectFiles_Click;
            
            // txtOutput
            
            txtOutput.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            txtOutput.Font = new Font("Microsoft Sans Serif", 9F);
            txtOutput.Location = new Point(12, 55);
            txtOutput.Multiline = true;
            txtOutput.Name = "txtOutput";
            txtOutput.ScrollBars = ScrollBars.Both;
            txtOutput.Size = new Size(760, 394);
            txtOutput.TabIndex = 4;
            
            // openFileDialog
            
            openFileDialog.Filter = "Event Log Files (*.evtx)|*.evtx";
            openFileDialog.Multiselect = true;
            openFileDialog.Title = "Select EVTX Files";
            
            // chkUseTimeFilter
            
            chkUseTimeFilter.AutoSize = true;
            chkUseTimeFilter.Location = new Point(170, 20);
            chkUseTimeFilter.Name = "chkUseTimeFilter";
            chkUseTimeFilter.Size = new Size(160, 24);
            chkUseTimeFilter.TabIndex = 1;
            chkUseTimeFilter.Text = "Filter by time range";
            chkUseTimeFilter.UseVisualStyleBackColor = true;
            
            // dtpStart
            
            dtpStart.CustomFormat = "yyyy-MM-dd HH:mm:ss";
            dtpStart.Format = DateTimePickerFormat.Custom;
            dtpStart.Location = new Point(320, 16);
            dtpStart.Name = "dtpStart";
            dtpStart.ShowUpDown = true;
            dtpStart.Size = new Size(180, 27);
            dtpStart.TabIndex = 2;
            dtpStart.Value = new DateTime(2025, 11, 19, 23, 36, 8, 578);
            
            // dtpEnd
            
            dtpEnd.CustomFormat = "yyyy-MM-dd HH:mm:ss";
            dtpEnd.Format = DateTimePickerFormat.Custom;
            dtpEnd.Location = new Point(510, 16);
            dtpEnd.Name = "dtpEnd";
            dtpEnd.ShowUpDown = true;
            dtpEnd.Size = new Size(180, 27);
            dtpEnd.TabIndex = 3;
            dtpEnd.Value = new DateTime(2025, 11, 20, 3, 36, 8, 580);
            
            // MainForm
            
            ClientSize = new Size(784, 461);
            Controls.Add(btnSelectFiles);
            Controls.Add(chkUseTimeFilter);
            Controls.Add(dtpStart);
            Controls.Add(dtpEnd);
            Controls.Add(txtOutput);
            Icon = (Icon)resources.GetObject("$this.Icon");
            Name = "MainForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "SeshatEVTX Analyzer";
            Load += MainForm_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        private void MainForm_Load(object? sender, EventArgs e)
        {
        }

        private async void BtnSelectFiles_Click(object? sender, EventArgs e)
        {
            if (openFileDialog.ShowDialog() != DialogResult.OK)
                return;

            DateTime? start = null;
            DateTime? end = null;

            if (chkUseTimeFilter.Checked)
            {
                start = dtpStart.Value;
                end = dtpEnd.Value;

                if (end < start)
                {
                    MessageBox.Show("End time must be after start time.", "Invalid Time Range",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }

            txtOutput.Text = $"Analyzing {openFileDialog.FileNames.Length} files...\nPlease wait... (This may take a moment)";
            btnSelectFiles.Enabled = false;

            try
            {
                AnalysisResult result = await EvtxAnalysisService.RunAnalysisAsync(openFileDialog.FileNames, start, end);

                txtOutput.Text = result.ReportText;

                var reply = MessageBox.Show("Analysis Complete.\n\nDo you want to save the CSV reports?", "Save Results", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                if (reply == DialogResult.Yes)
                {
                    folderBrowserDialog.Description = "Select a folder to save the CSV reports";
                    if (folderBrowserDialog.ShowDialog() == DialogResult.OK)
                    {
                        ReportGenerator.GenerateCsvOutputs(folderBrowserDialog.SelectedPath, result.TimelineData, result.FullLogData);
                        MessageBox.Show($"Files saved to:\n{folderBrowserDialog.SelectedPath}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                txtOutput.Text = $"An error occurred: {ex.Message}";
            }
            finally
            {
                btnSelectFiles.Enabled = true;
            }
        }
    }
}