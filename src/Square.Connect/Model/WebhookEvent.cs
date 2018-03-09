using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;


namespace Square.Connect.Model
{
	/// <summary>
	/// Encapsulates the event sent by a Square Webhook. Use the static methods to
	/// parse and verify an event.
	/// </summary>
	[DataContract]
	public class WebhookEvent
			: IEquatable<WebhookEvent>
	{
		/// <summary>
		/// Returns the Http Header name of the Square signature sent on Webhook events:
		/// <c>"X-Square-Signature"</c>.
		/// </summary>
		public static string SquareSignatureHeaderName
			=> "X-Square-Signature";

		/// <summary>
		/// Is a new encoding with no BOM, and riases exceptions on bad formats.
		/// </summary>
		public static UTF8Encoding Utf8
			=> new UTF8Encoding(false, true);

		/// <summary>
		/// Utility method marshalls the given <see cref="SecureString"/> TO PLAIN TEXT now.
		/// </summary>
		/// <returns>May be null or empty.</returns>
		public static string MarshalSecureString(SecureString password)
			=> password == null
					? null
					: Marshal.PtrToStringBSTR(Marshal.SecureStringToBSTR(password));


		/// <summary>
		/// This method parses the object from the request, verifies the signature,
		/// and returns an instance indicating <see cref="IsSquareSignatureValid"/>. The
		/// generic acgument is provded to allow constructing a subclass that you choose:
		/// it must implement <c>new()</c>. The returned <see cref="Id"/> will be set to 
		/// the <see cref="EntityId"/> if it is null here.
		/// </summary>
		/// <typeparam name="T">The specific <see cref="WebhookEvent"/> class that will
		/// be created and returned.</typeparam>
		/// <param name="httpRequestMessage">Required.</param>
		/// <param name="squareSignatureKey">The Square signature key: this will be disposed here
		/// now.</param>
		/// <param name="webhookEventId">Note that this may be null: this sets the
		/// <see cref="Id"/> of the returned object; but if null, the Id will be set to the
		/// parsed <see cref="EntityId"/>. (If whitespace or empty, the property IS set to
		/// THIS value.)</param>
		/// <returns>Not null.</returns>
		/// <exception cref="ArgumentNullException"></exception>
		public static async Task<T> ParseAsync<T>(
				HttpRequestMessage httpRequestMessage,
				SecureString squareSignatureKey,
				string webhookEventId = null)
				where T : WebhookEvent, new()
		{
			if (httpRequestMessage == null)
				throw new ArgumentNullException(nameof(httpRequestMessage));
			return WebhookEvent.Parse<T>(
					await httpRequestMessage.Content.ReadAsStringAsync(),
					httpRequestMessage.RequestUri.ToString(),
					httpRequestMessage.Headers.GetValues(WebhookEvent.SquareSignatureHeaderName)
							.FirstOrDefault(),
					squareSignatureKey,
					webhookEventId);
		}

		/// <summary>
		/// This method parses the object from the Json request body, verifies the signature,
		/// and returns an instance indicating <see cref="IsSquareSignatureValid"/>. The
		/// generic acgument is provded to allow constructing a subclass that you choose:
		/// it must implement <c>new()</c>.
		/// </summary>
		/// <typeparam name="T">The specific <see cref="WebhookEvent"/> class that will
		/// be created and returned.</typeparam>
		/// <param name="requestBody">Required.</param>
		/// <param name="webhookNotificationUrl">Required.</param>
		/// <param name="squareSignature">Required.</param>
		/// <param name="squareSignatureKey">The Square signature key: this will be disposed here
		/// now.</param>
		/// <param name="webhookEventId">Note that this may be null: this sets the
		/// <see cref="Id"/> of the returned object; but if null, the Id will be set to the
		/// parsed <see cref="EntityId"/>. (If whitespace or empty, the property IS set to
		/// THIS value.)</param>
		/// <returns>Not null.</returns>
		/// <exception cref="ArgumentNullException"></exception>
		public static T Parse<T>(
				string requestBody,
				string webhookNotificationUrl,
				string squareSignature,
				SecureString squareSignatureKey,
				string webhookEventId = null)
				where T : WebhookEvent, new()
		{
			dynamic requestData = JsonConvert.DeserializeObject(requestBody);
			string entityId = requestData?.entity_id?.ToString();
			string locationId = requestData?.location_id?.ToString();
			string merchantId = requestData?.merchant_id?.ToString();
			string eventType = requestData?.event_type?.ToString();
			return new T
			{
				Id = webhookEventId ?? entityId,
				EntityId = entityId,
				LocationId = locationId,
				MerchantId = merchantId,
				EventType = eventType,
				SquareSignature = squareSignature,
				IsSquareSignatureValid
						= WebhookEvent.VerifySignature(
								requestBody,
								webhookNotificationUrl,
								squareSignature,
								squareSignatureKey),
			};
		}

		/// <summary>
		/// Computes the HMAC-SHA1 signature of a string consisting of your webhook
		/// notification URL followed immediately by the body of the request (no whitespace);
		/// and compares that to the expected <see cref="SquareSignature"/>.
		/// </summary>
		/// <param name="requestBody">Required.</param>
		/// <param name="webhookNotificationUrl">Required.</param>
		/// <param name="squareSignature">Required.</param>
		/// <param name="squareSignatureKey">The Square signature key: this will be disposed here
		/// now.</param>
		/// <returns>True if the signatures match.</returns>
		/// <exception cref="ArgumentNullException"></exception>
		public static bool VerifySignature(
				string requestBody,
				string webhookNotificationUrl,
				string squareSignature,
				SecureString squareSignatureKey)
		{
			if (string.IsNullOrWhiteSpace(requestBody))
				throw new ArgumentNullException(nameof(requestBody));
			if (string.IsNullOrWhiteSpace(webhookNotificationUrl))
				throw new ArgumentNullException(nameof(webhookNotificationUrl));
			if (string.IsNullOrWhiteSpace(squareSignature))
				throw new ArgumentNullException(nameof(squareSignature));
			return string.Equals(
					squareSignature,
					WebhookEvent.ComputeSignature(
							requestBody,
							webhookNotificationUrl,
							squareSignatureKey),
					StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// This is a utility implementation method that computes the message signature for a
		/// Square Webhook event.
		/// </summary>
		/// <param name="requestBody">Must be the body of the Webhook.</param>
		/// <param name="webhookNotificationUrl">Must be the Url of the Webhook handler.</param>
		/// <param name="squareSignatureKey">The Squate signature key ---  this will be disposed here
		/// now.</param>
		/// <returns>Not null.</returns>
		/// <exception cref="ArgumentNullException"></exception>
		public static string ComputeSignature(
				string requestBody,
				string webhookNotificationUrl,
				SecureString squareSignatureKey)
		{
			if (squareSignatureKey == null)
				throw new ArgumentNullException(nameof(squareSignatureKey));
			if (string.IsNullOrWhiteSpace(requestBody))
				throw new ArgumentNullException(nameof(requestBody));
			if (string.IsNullOrWhiteSpace(webhookNotificationUrl))
				throw new ArgumentNullException(nameof(webhookNotificationUrl));
			if (squareSignatureKey == null)
				throw new ArgumentNullException(nameof(squareSignatureKey));
			using (squareSignatureKey) {
				using (HMACSHA1 hmacSha1
						= new HMACSHA1(
								WebhookEvent.Utf8.GetBytes(
										WebhookEvent.MarshalSecureString(squareSignatureKey)))) {
					return Convert.ToBase64String(
							hmacSha1.ComputeHash(
									WebhookEvent.Utf8.GetBytes(
											$"{webhookNotificationUrl}{requestBody}")));
				}
			}
		}


		/// <summary>
		/// Default constructor: sets nothing.
		/// </summary>
		public WebhookEvent() { }

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="id">NOT tested.</param>
		/// <param name="entityId">NOT tested.</param>
		/// <param name="locationId">NOT tested.</param>
		/// <param name="merchantId">NOT tested.</param>
		/// <param name="eventType">NOT tested.</param>
		/// <param name="squareSignature">NOT tested.</param>
		/// <param name="isSquareSignatureValid">NOT tested.</param>
		public WebhookEvent(
				string id,
				string entityId,
				string locationId,
				string merchantId,
				string eventType,
				string squareSignature,
				bool isSquareSignatureValid)
		{
			Id = id;
			EntityId = entityId;
			LocationId = locationId;
			MerchantId = merchantId;
			EventType = eventType;
			SquareSignature = squareSignature;
			IsSquareSignatureValid = isSquareSignatureValid;
		}

		/// <summary>
		/// Constructor: sets this <see cref="Id"/> to the <see cref="EntityId"/>.
		/// </summary>
		/// <param name="entityId">NOT tested.</param>
		/// <param name="locationId">NOT tested.</param>
		/// <param name="merchantId">NOT tested.</param>
		/// <param name="eventType">NOT tested.</param>
		/// <param name="squareSignature">NOT tested.</param>
		/// <param name="isSquareSignatureValid">NOT tested.</param>
		public WebhookEvent(
				string entityId,
				string locationId,
				string merchantId,
				string eventType,
				string squareSignature,
				bool isSquareSignatureValid)
				: this(
						entityId,
						entityId,
						locationId,
						merchantId,
						eventType,
						squareSignature,
						isSquareSignatureValid)
		{ }


		/// <summary>
		/// Our database Id. This could explicitly be set to the <see cref="EntityId"/> in
		/// the constructor.
		/// </summary>
		[DataMember(Name = "id")]
		public string Id { get; protected set; }

		/// <summary>
		/// The Square Entity Id.
		/// </summary>
		[DataMember]
		public string EntityId { get; protected set; }

		/// <summary>
		/// Our LocationId.
		/// </summary>
		[DataMember]
		public string LocationId { get; protected set; }

		/// <summary>
		/// Our Merchant Id.
		/// </summary>
		[DataMember]
		public string MerchantId { get; protected set; }

		/// <summary>
		/// The Square Webhook type.
		/// </summary>
		[DataMember]
		public string EventType { get; protected set; }

		/// <summary>
		/// The X-Square-Signature header.
		/// </summary>
		[DataMember]
		public string SquareSignature { get; protected set; }

		/// <summary>
		/// Set on construction if the <see cref="SquareSignature"/> was validated.
		/// </summary>
		[DataMember]
		public bool IsSquareSignatureValid { get; protected set; }


		[SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
		public override int GetHashCode()
		{
			unchecked {
				int hash = 23;
				hash = ((hash * 37) + Id?.GetHashCode()) ?? 0;
				hash = ((hash * 37) + EntityId?.GetHashCode()) ?? 0;
				hash = ((hash * 37) + LocationId?.GetHashCode()) ?? 0;
				hash = ((hash * 37) + MerchantId?.GetHashCode()) ?? 0;
				hash = ((hash * 37) + EventType?.GetHashCode()) ?? 0;
				hash = ((hash * 37) + SquareSignature?.GetHashCode()) ?? 0;
				hash = (hash * 37)
						+ (IsSquareSignatureValid
								? 1
								: 0);
				return hash;
			}
		}

		public override bool Equals(object obj)
			=> Equals(obj as WebhookEvent);

		public bool Equals(WebhookEvent other)
			=> (other != null)
					&& string.Equals(Id, other.Id, StringComparison.InvariantCultureIgnoreCase)
					&& string.Equals(EntityId, other.EntityId, StringComparison.InvariantCultureIgnoreCase)
					&& string.Equals(LocationId, other.LocationId, StringComparison.InvariantCultureIgnoreCase)
					&& string.Equals(MerchantId, other.MerchantId, StringComparison.InvariantCultureIgnoreCase)
					&& string.Equals(EventType, other.EventType, StringComparison.InvariantCultureIgnoreCase)
					&& string.Equals(
							SquareSignature,
							other.SquareSignature,
							StringComparison.InvariantCultureIgnoreCase)
					&& (IsSquareSignatureValid == other.IsSquareSignatureValid);

		public override string ToString()
			=> $"{GetType().Name} {JsonConvert.SerializeObject(this, Formatting.Indented)}";
	}
}
