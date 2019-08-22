using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Net.Http.Headers;
using PgpDecryptApp.Helpers;
using PgpDecryptApp.Services;

namespace PgpDecryptApp.Controllers
{
    public class DecryptController : Controller
    {
        private readonly IDecryptService _decryptService;
        private readonly IConfiguration _configuration;

        public DecryptController(IDecryptService decryptService, IConfiguration configuration)
        {
            _decryptService = decryptService;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult UploadFile(List<IFormFile> files)
        {   
            if (files != null && files.Count > 0)
            {
                var file = files[0];
                using (var inpSteram = file.OpenReadStream())
                {
                    using (var privateKey = new FileStream(_configuration.GetValue<string>("PrivateKeyFile"), FileMode.Open))
                    {
                        var decodedFile = _decryptService.Decrypt(inpSteram, privateKey, _configuration.GetValue<string>("PassPhrase"));
                        return File(FileHelpers.ReadFully(decodedFile.GetDataStream()), "application/octet-stream", fileDownloadName: decodedFile.FileName);
                    }
                    
                }
                
            }
            return RedirectToAction("Index");
        }
    }
}