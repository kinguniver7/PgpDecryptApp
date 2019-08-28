using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Configuration;
using Microsoft.Net.Http.Headers;
using PgpDecryptApp.Helpers;
using PgpDecryptApp.Services;

namespace PgpDecryptApp.Controllers
{
    public class DecryptController : Controller
    {
        private readonly IPgpService _pgpService;
        private readonly IConfiguration _configuration;

        public DecryptController(IPgpService pgpService, IConfiguration configuration)
        {
            _pgpService = pgpService;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult DecodeFile(List<IFormFile> files)
        {   
            if (files != null && files.Count > 0)
            {
                var file = files[0];
                byte[] bytes = null;
                string originalFileName = null;
                using (var inpSteram = file.OpenReadStream())
                {                    
                    using (var privateKey = new FileStream(_configuration.GetValue<string>("PrivateKeyFile"), FileMode.Open))
                    {
                        var decodedFile = _pgpService.Decrypt(inpSteram, privateKey, _configuration.GetValue<string>("PassPhrase"));
                        
                        if (decodedFile == null || string.IsNullOrWhiteSpace(decodedFile.FileName))
                        {
                            TempData["msg"] = "File name not found. Please try again!";
                            return RedirectToAction("Index");
                        }
                        originalFileName = decodedFile.FileName;
                        bytes = FileHelpers.ReadFully(decodedFile.GetDataStream()); 
                    }                    
                }
                new FileExtensionContentTypeProvider().TryGetContentType(originalFileName, out string contentType);
                
                return File(bytes, contentType ?? "application/octet-stream", fileDownloadName: originalFileName);
            }
            else
            {
                TempData["msg"] = "File not found. Please try again!";
            }
            return RedirectToAction("Index");
        }
    }
}