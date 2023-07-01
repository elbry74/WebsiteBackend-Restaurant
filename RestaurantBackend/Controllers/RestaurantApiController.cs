using ContactUsBackend.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Net.Http;
using System.Web.Http;
using System.Net.Mail;
using iTextSharp.text;
using iTextSharp.text.pdf;
using System.IO;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Drawing;
using System.Drawing.Imaging;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Data.Entity;

namespace ContactUsBackend.Controllers
{
    public class ContactApiController : ApiController
    {
        [HttpGet]
        [Route("api/ContactApiController/GetAllData")]
        public HttpResponseMessage GetAllData()
        {
            using (contact_usEntities4 dbcontext = new contact_usEntities4())
            {
                return Request.CreateResponse(HttpStatusCode.OK, dbcontext.contacts.Where(e => e.Flag_show == 0).ToList());
            }
        }

        [HttpGet]
        [Route("api/ContactApiController/Get/{id}")]
        public HttpResponseMessage Get(int id)
        {
            using (contact_usEntities4 dbcontext = new contact_usEntities4())
            {
                var emp = dbcontext.contacts.FirstOrDefault(e => e.id == id);
                if (emp != null)
                {
                    return Request.CreateResponse(HttpStatusCode.OK, emp);
                }
                else
                {
                    return Request.CreateErrorResponse(HttpStatusCode.NotFound, "User with Id " + id + " not found in database");
                }
            }
        }


        [HttpPost]
        [Route("api/ContactApiController/Post")]
        public HttpResponseMessage Post([FromBodyAttribute] contact contact)
        {

            using (contact_usEntities4 dbcontext = new contact_usEntities4())
            {
                if (contact != null)
                {
                    dbcontext.contacts.Add(contact);
                    contact.Flag_show = 0;
                    dbcontext.SaveChanges();
                    return Request.CreateResponse(HttpStatusCode.Created, contact);
                }
                else
                {
                    return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Please provide input data to send massage");
                }
            }

        }


        [HttpPost]
        [Route("api/ContactApiController/reply")]
        public HttpResponseMessage reply([FromBodyAttribute] contact contact)
        {
            using (contact_usEntities4 dbcontext = new contact_usEntities4())
            {
                if (contact != null)
                {
                    var cont = dbcontext.contacts.Where(x => x.id == contact.id).FirstOrDefault();
                    cont.Flag_show = 1;

                    dbcontext.SaveChanges();
                    return Request.CreateErrorResponse(HttpStatusCode.OK, "succeed");
                }
                else
                {
                    return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Please provide input data to send massage");
                }
            }

        }


        [HttpPost]
        [Route("api/ContactApiController/SendEmail")]
        public IHttpActionResult SendEmail(contact contact)
        {

            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress("info@tamweely.local");
            mailMessage.To.Add("mahmoudyousef199333@gmail.com");
            mailMessage.Subject = contact.subject;
            mailMessage.Body = contact.massage;

            SmtpClient smtpClient = new SmtpClient();
            smtpClient.Host = "mail.tamweely.local";
            smtpClient.Port = 587;
            smtpClient.UseDefaultCredentials = false;
            smtpClient.Credentials = new NetworkCredential("info@tamweely.local", "T@mweely@2020");
            smtpClient.EnableSsl = false;

            try
            {
                smtpClient.Send(mailMessage);
                Console.WriteLine("Email Sent Successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            return Ok();
        }



        [HttpGet]
        [Route("api/ContactApiController/downloadPdf/{id}")]
        public HttpResponseMessage downloadPdf(int id)
        {
            using (contact_usEntities4 dbcontext = new contact_usEntities4())
            {
                // Retrieve the user data for the specified ID
                var userData = dbcontext.contacts.FirstOrDefault(u => u.id == id);

                if (userData == null)
                {
                    return Request.CreateErrorResponse(HttpStatusCode.NotFound, "User not found for the specified ID.");
                }

                // Create a new PDF document
                var document = new Document();
                var output = new MemoryStream();
                var writer = PdfWriter.GetInstance(document, output);
                document.Open();

                // Create a table with three columns and a single row
                var table = new PdfPTable(3);
                table.WidthPercentage = 100;
                table.SetWidths(new float[] { 2f, 3f, 4f });

                // Add table headers
                table.AddCell(new PdfPCell(new Phrase("Email")));
                table.AddCell(new PdfPCell(new Phrase("Subject")));
                table.AddCell(new PdfPCell(new Phrase("Message")));

                // Add the user data to the table
                table.AddCell(new PdfPCell(new Phrase(userData.email)));
                table.AddCell(new PdfPCell(new Phrase(userData.subject)));
                table.AddCell(new PdfPCell(new Phrase(userData.massage)));

                // Add the table to the document
                document.Add(table);

                // Close the document
                document.Close();

                // Set up the HTTP response
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ByteArrayContent(output.ToArray());
                response.Content.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment");
                response.Content.Headers.ContentDisposition.FileName = "output.pdf";
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
                response.Content.Headers.ContentLength = output.ToArray().Length;
                return response;
            }
        }


        [HttpPost]
        [Route("api/ContactApiController/UploadImage")]
        public async Task<IHttpActionResult> UploadImage(string code = null)
        {
            try
            {
                var httpRequest = HttpContext.Current.Request;
                if (httpRequest.Files.Count == 0)
                {
                    return BadRequest("No image found in request");
                }

                var postedFile = httpRequest.Files[0];
                var fileName = postedFile.FileName;
                var directoryPath = HttpContext.Current.Server.MapPath("~/assets/images/brands/");
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                // Check if an image with the same name already exists
                var filePath = Path.Combine(directoryPath, fileName);
                if (File.Exists(filePath))
                {
                    // Generate a new file name based on the current date and time
                    var timestamp = DateTime.Now.ToString("yyyyMMddHHmmssfff");
                    var fileExtension = Path.GetExtension(fileName);
                    var newFileName = $"{Path.GetFileNameWithoutExtension(fileName)}_{timestamp}{fileExtension}";
                    filePath = Path.Combine(directoryPath, newFileName);
                }

                // Save the image file
                await Task.Run(() => postedFile.SaveAs(filePath));

                // Generate a unique code for the image if one was not provided
                if (string.IsNullOrEmpty(code))
                {
                    code = Guid.NewGuid().ToString();
                }

                // Save the image path and code to the database
                using (var db = new contact_usEntities4())
                {
                    var image = new brandsImage
                    {
                        ImagePath = filePath,
                        Code = code
                    };
                    db.brandsImages.Add(image);
                    db.SaveChanges();
                }

                return Ok(code);
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }



        //[HttpPost]
        //[Route("api/ContactApiController/UploadImageByCode")]
        //public async Task<IHttpActionResult> UploadImageByCode(string code = null)
        //{
        //    try
        //    {
        //        var httpRequest = HttpContext.Current.Request;
        //        if (httpRequest.Files.Count == 0)
        //        {
        //            return BadRequest("No image found in request");
        //        }

        //        var postedFile = httpRequest.Files[0];
        //        var fileName = postedFile.FileName;
        //        var directoryPath = HttpContext.Current.Server.MapPath("~/projectImages/user/profile");
        //        if (!Directory.Exists(directoryPath))
        //        {
        //            Directory.CreateDirectory(directoryPath);
        //        }

        //        // Check if an image with the same name already exists
        //        var filePath = Path.Combine(directoryPath, fileName);
        //        if (File.Exists(filePath))
        //        {
        //            // Generate a new file name based on the current date and time
        //            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmssfff");
        //            var fileExtension = Path.GetExtension(fileName);
        //            var newFileName = $"{Path.GetFileNameWithoutExtension(fileName)}_{timestamp}{fileExtension}";
        //            filePath = Path.Combine(directoryPath, newFileName);
        //        }

        //        // Save the image file
        //        await Task.Run(() => postedFile.SaveAs(filePath));

        //        // Generate a unique code for the image if one was not provided
        //        if (string.IsNullOrEmpty(code))
        //        {
        //            code = Guid.NewGuid().ToString();
        //        }

        //        // Save the image path and code to the database
        //        using (var db = new contact_usEntities4())
        //        {
        //            var image = new brandsImage
        //            {
        //                ImagePath = filePath,
        //                Code = code
        //            };
        //            db.brandsImages.Add(image);
        //            db.SaveChanges();
        //        }

        //        return Ok(code);
        //    }
        //    catch (Exception ex)
        //    {
        //        return InternalServerError(ex);
        //    }
        //}




        [HttpGet]
        [Route("api/ContactApiController/GetAllImages")]
        public IHttpActionResult GetAllImages()
       {
            try
            {
                using (var db = new contact_usEntities4())
                {
                    var images = db.brandsImages.ToList();
                    if (images.Count == 0)
                    {
                        return NotFound();
                    }

                    var result = new List<object>();
                    foreach (var image in images)
                    {
                        using (var fileStream = new FileStream(image.ImagePath, FileMode.Open, FileAccess.Read))
                        {
                            var buffer = new byte[fileStream.Length];
                            fileStream.Read(buffer, 0, (int)fileStream.Length);
                            var base64 = Convert.ToBase64String(buffer);
                            result.Add(new
                            {
                                Code = image.Code,
                                ImageData = base64,
                                ContentType = "image/jpeg" // or the actual content type of the image file
                            });
                        }
                    }
                    return Ok(result);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

      

        [HttpGet]
        [Route("api/ContactApiController/GetAllImageCodes")]
        public IHttpActionResult GetAllImageCodes()
        {
            try
            {
                using (var db = new contact_usEntities4())
                {
                    var images = db.brandsImages.ToList();
                    if (images.Count == 0)
                    {
                        return NotFound();
                    }

                    var result = images.Select(i => i.Code).ToList();
                    return Ok(result);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }




        [HttpGet]
        [Route("api/ContactApiController/GetImagesByCode/{code}")]
        public IHttpActionResult GetImagesByCode(string code)
        {
            try
            {
                using (var db = new contact_usEntities4())
                {
                    var image = db.brandsImages.FirstOrDefault(i => i.Code == code);
                    if (image == null)
                    {
                        return NotFound();
                    }

                    var fileStream = new FileStream(image.ImagePath, FileMode.Open, FileAccess.Read);
                    var response = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StreamContent(fileStream)
                    };
                    response.Content.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");
                    return ResponseMessage(response);
                }
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }



        //[HttpGet]
        //[Route("api/ContactApiController/GetImage/{code}")]
        //public IHttpActionResult GetImage(string code)
        //{
        //    if (string.IsNullOrEmpty(code))
        //    {
        //        return BadRequest("No code provided");
        //    }

        //    using (var db = new contact_usEntities4())
        //    {
        //        var image = db.brandsImages.FirstOrDefault(i => i.Code == code);
        //        if (image == null)
        //        {
        //            Console.WriteLine($"Image with code {code} not found");
        //            return NotFound();
        //        }

        //        Console.WriteLine($"Retrieving image with code {code}");

        //        return Ok(image.ImagePath);
        //    }
        //}


        [HttpPost]
        [Route("api/ContactApiController/UpdateImage/{code}")]
        public async Task<IHttpActionResult> UpdateImage(string code)
        {
            try
            {
                var httpRequest = HttpContext.Current.Request;
                if (httpRequest.Files.Count == 0)
                {
                    return BadRequest("No image found in request");
                }

                var postedFile = httpRequest.Files[0];
                var fileName = postedFile.FileName;
                var directoryPath = HttpContext.Current.Server.MapPath("~/assets/images/brands/");
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                // Delete the old image file
                using (var db = new contact_usEntities4())
                {
                    var image = db.brandsImages.FirstOrDefault(i => i.Code == code);
                    if (image != null)
                    {
                        var oldFilePath = image.ImagePath;
                        if (File.Exists(oldFilePath))
                        {
                            File.Delete(oldFilePath);
                        }
                    }
                }



                var filePath = Path.Combine(directoryPath, fileName);
                if (File.Exists(filePath))
                {
                    // Generate a new file name based on the current date and time
                    var timestamp = DateTime.Now.ToString("yyyyMMddHHmmssfff");
                    var fileExtension = Path.GetExtension(fileName);
                    var newFileName = $"{Path.GetFileNameWithoutExtension(fileName)}_{timestamp}{fileExtension}";
                    filePath = Path.Combine(directoryPath, newFileName);
                }

                // Save the image file
                await Task.Run(() => postedFile.SaveAs(filePath));

                // Update the image path for the specified code in the database
                using (var db = new contact_usEntities4())
                {
                    var image = db.brandsImages.FirstOrDefault(i => i.Code == code);
                    if (image == null)
                    {
                        return NotFound();
                    }

                    image.ImagePath = filePath;
                    db.SaveChanges();
                }

                return Ok("Image updated successfully.");
            }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
        }

        [HttpDelete]
        [Route("api/ContactApiController/DeleteImage/{code}")]
        public IHttpActionResult DeleteImage(string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("No code provided");
            }

            using (var db = new contact_usEntities4())
            {
                var image = db.brandsImages.FirstOrDefault(i => i.Code == code);
                if (image == null)
                {
                    Console.WriteLine($"Image with code {code} not found");
                    return NotFound();
                }

                Console.WriteLine($"Deleting image with code {code}");
                db.brandsImages.Remove(image);
                db.SaveChanges();

                File.Delete(image.ImagePath);

                return Ok();
            }
        }

        [HttpPost]
        [Route("api/ContactApiController/register", Name = "Register")]
        public async Task<IHttpActionResult> RegisterMethod([FromBody] Register register)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            using (var db = new contact_usEntities12())
            {
                // Check if email already exists
                if (await db.Registers.AnyAsync(r => r.email == register.email))
                {
                    return BadRequest("Email already exists");
                }

                // Create a new Register object and add it to the database
                var newRegister = new Register
                {
                    name = register.name,
                    address = register.address,
                    email = register.email,
                    phone = register.phone,
                    password = register.password
                };
                db.Registers.Add(newRegister);
                await db.SaveChangesAsync();

                return CreatedAtRoute("Register", new { id = newRegister.id }, newRegister);
            }
        }
        [HttpPost]
        [Route("api/ContactApiController/login")]
        public async Task<IHttpActionResult> LoginMethod([FromBody] Register login)
        {
         

            using (var db = new contact_usEntities11())
            {
                // Check if user with the given email and password exists in the database
                var user = await db.Registers.FirstOrDefaultAsync(r => r.email == login.email && r.password == login.password);

                if (user == null)
                {
                    // User not found in the database
                    return BadRequest("Invalid email or password");
                }
                else
                {
                    // User found in the database
                    // Generate a token for the user
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var keyLength = 256 / 8; // 256 bits
                    var key = new byte[keyLength];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(key);
                    }
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                    new Claim(ClaimTypes.Name, user.email)
                        }),
                        Expires = DateTime.UtcNow.AddDays(1),
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                    };
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    var tokenString = tokenHandler.WriteToken(token);

                    // Return the token to the client
                    return Ok(new { Token = tokenString });
                }
            }
        }


        [HttpPost]
        [Route("api/ContactApiController/ForgetPasswordEmail")]
        public async Task<IHttpActionResult> ForgetPasswordEmail(Register model)
        {
          

            using (var db = new contact_usEntities12())
            {
                // Check if a user with the given email exists in the database
                var user = await db.Registers.FirstOrDefaultAsync(r => r.email == model.email);

                if (user == null)
                {
                    // User not found in the database
                    return BadRequest("Invalid email");
                }

                // Generate a password reset token for the user
                var tokenHandler = new JwtSecurityTokenHandler();
                var keyLength = 256 / 8; // 256 bits
                var key = new byte[keyLength];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(key);
                }
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                new Claim(ClaimTypes.Name, user.email)
                    }),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                // Build the email message
                var callbackUrl = $"{model.name}/resetpassword?email={user.email}&token={tokenString}";
                var emailBody = $"Please reset your password by clicking <a href='{callbackUrl}'>here</a>";
                var message = new MailMessage();
                message.From = new MailAddress("info@tamweely.local");
                message.To.Add(new MailAddress(user.email));
                message.Subject = "Reset Password";
                message.Body = emailBody;
                message.IsBodyHtml = true;

                // Set up the SMTP client
                using (var smtpClient = new SmtpClient())
                {
                    smtpClient.Host = "mail.tamweely.local";
                    smtpClient.Port = 587;
                    smtpClient.Credentials = new NetworkCredential("info@tamweely.local", "T@mweely@2020");
                    smtpClient.EnableSsl = true;

                    try
                    {
                        // Send the email
                        await smtpClient.SendMailAsync(message);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: " + ex.Message);
                        return BadRequest("Failed to send email");
                    }
                }

                return Ok();
            }
        }
    }
}

