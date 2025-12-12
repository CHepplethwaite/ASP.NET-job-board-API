using backend.Core.DTOs.User;
using backend.Core.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace backend.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ProfileController : ControllerBase
    {
        private readonly IProfileService _profileService;
        private readonly ILogger<ProfileController> _logger;

        public ProfileController(IProfileService profileService, ILogger<ProfileController> logger)
        {
            _profileService = profileService;
            _logger = logger;
        }

        [HttpGet("me")]
        public async Task<IActionResult> GetMyProfile()
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var profile = await _profileService.GetUserProfileAsync(userId);
                return Ok(profile);
            }
            catch (NotFoundException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting profile");
                return StatusCode(500, new { message = "An error occurred getting profile" });
            }
        }

        [HttpPut("update-basic")]
        public async Task<IActionResult> UpdateBasicProfile([FromBody] UpdateBasicProfileRequest request)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                await _profileService.UpdateBasicProfileAsync(userId, request);
                return Ok(new { message = "Profile updated successfully" });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating profile");
                return StatusCode(500, new { message = "An error occurred updating profile" });
            }
        }

        [HttpPost("upload-cv")]
        [Authorize(Roles = "JobSeeker")]
        public async Task<IActionResult> UploadCv(IFormFile file)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var result = await _profileService.UploadCvAsync(userId, file);
                return Ok(new
                {
                    message = "CV uploaded successfully",
                    cvUrl = result.CvUrl,
                    fileName = result.FileName,
                    uploadDate = result.UploadDate
                });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading CV");
                return StatusCode(500, new { message = "An error occurred uploading CV" });
            }
        }

        [HttpPost("upload-profile-picture")]
        public async Task<IActionResult> UploadProfilePicture(IFormFile file)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var result = await _profileService.UploadProfilePictureAsync(userId, file);
                return Ok(new
                {
                    message = "Profile picture uploaded successfully",
                    profilePictureUrl = result.ProfilePictureUrl
                });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading profile picture");
                return StatusCode(500, new { message = "An error occurred uploading profile picture" });
            }
        }

        [HttpDelete("delete-cv")]
        [Authorize(Roles = "JobSeeker")]
        public async Task<IActionResult> DeleteCv()
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                await _profileService.DeleteCvAsync(userId);
                return Ok(new { message = "CV deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting CV");
                return StatusCode(500, new { message = "An error occurred deleting CV" });
            }
        }

        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                await _profileService.ChangePasswordAsync(userId, request);
                return Ok(new { message = "Password changed successfully" });
            }
            catch (ValidationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                return StatusCode(500, new { message = "An error occurred changing password" });
            }
        }
    }
}